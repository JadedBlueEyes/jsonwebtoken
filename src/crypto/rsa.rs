// use ring::{rand, signature};
use crate::errors::{ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};
use crate::{errors, Algorithm};
use rsa::SignatureScheme;
use rsa::{pss::Pss, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The actual RSA signing + encoding
/// The key needs to be in binary DER-encoded ASN.1 format
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
pub(crate) fn sign(alg: Algorithm, key: &RsaPrivateKey, message: &str) -> Result<String> {
    let digest: Vec<u8> = match alg {
        // PaddingScheme::OAEP {digest, ..} => {
        //     digest.update(message.as_bytes());
        //     digest.finalize_reset()
        // },
        // None => message.as_bytes().into(),
        Algorithm::RS256 | Algorithm::PS256 => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.as_slice().to_vec()
        }
        Algorithm::RS384 | Algorithm::PS384 => {
            let mut hasher = Sha384::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.as_slice().to_vec()
        }
        Algorithm::RS512 | Algorithm::PS512 => {
            let mut hasher = Sha512::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.as_slice().to_vec()
        }
        _ => unimplemented!(),
    };

    let signatures_scheme_pkcs = match alg {
        Algorithm::RS256 => Some(Pkcs1v15Sign::new::<Sha256>()),
        Algorithm::RS384 => Some(Pkcs1v15Sign::new::<Sha384>()),
        Algorithm::RS512 => Some(Pkcs1v15Sign::new::<Sha512>()),
        _ => None,
    };

    let signatures_scheme_pss = match alg {
        Algorithm::PS256 => Some(Pss::new::<Sha256>()),
        Algorithm::PS384 => Some(Pss::new::<Sha384>()),
        Algorithm::PS512 => Some(Pss::new::<Sha512>()),
        _ => None,
    };

    let mut rng = rand::thread_rng();

    let signature = if let Some(signatures_scheme) = signatures_scheme_pkcs {
        // In versions pre 1.2.0, signatures did not use RNG.
        signatures_scheme.sign(Some(&mut rng), key, &digest).expect("failed to sign pkcs")
    } else if let Some(signatures_scheme) = signatures_scheme_pss {
        // PSS requires signing with RNG,otherwise it errors at runtime.
        key.sign_with_rng(&mut rng, signatures_scheme, &digest).expect("failed to sign pss")
        // signatures_scheme.sign(Some(&mut rng), key, &digest).expect("failed to sign pss")
    } else {
        return Err(ErrorKind::InvalidAlgorithmName.into());
    };

    Ok(b64_encode(&signature))
}

/// Checks that a signature is valid based on the (n, e) RSA pubkey components
pub(crate) fn verify(
    alg: Algorithm,
    signature: &str,
    message: &str,
    key: &RsaPublicKey,
) -> Result<bool> {
    let digest: Vec<u8> = match alg {
        // PaddingScheme::OAEP {digest, ..} => {
        //     digest.update(message.as_bytes());
        //     digest.finalize_reset()
        // },
        // None => message.as_bytes().into(),
        Algorithm::RS256 | Algorithm::PS256 => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS384 | Algorithm::PS384 => {
            let mut hasher = Sha384::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS512 | Algorithm::PS512 => {
            let mut hasher = Sha512::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        // Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
        //     message.as_bytes().to_vec()
        // }
        _ => unimplemented!(),
    };

    let signature_bytes = b64_decode(signature)?;

    let signatures_scheme_pkcs = match alg {
        Algorithm::RS256 => Some(Pkcs1v15Sign::new::<Sha256>()),
        Algorithm::RS384 => Some(Pkcs1v15Sign::new::<Sha384>()),
        Algorithm::RS512 => Some(Pkcs1v15Sign::new::<Sha512>()),
        _ => None,
    };

    let signatures_scheme_pss = match alg {
        Algorithm::PS256 => Some(Pss::new::<Sha256>()),
        Algorithm::PS384 => Some(Pss::new::<Sha384>()),
        Algorithm::PS512 => Some(Pss::new::<Sha512>()),
        _ => None,
    };

    if let Some(signatures_scheme) = signatures_scheme_pkcs {
        signatures_scheme
            .verify(key, &digest, &signature_bytes)
            .map_err(|_| errors::new_error(ErrorKind::InvalidSignature))?;
    } else if let Some(signatures_scheme) = signatures_scheme_pss {
        signatures_scheme
            .verify(key, &digest, &signature_bytes)
            .map_err(|_| errors::new_error(ErrorKind::InvalidSignature))?;
    } else {
        return Err(ErrorKind::InvalidAlgorithmName.into());
    };

    Ok(true)
}
