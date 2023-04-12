// use ring::{rand, signature};
use crate::errors::{ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};
use crate::{errors, Algorithm};
use rsa::{Pkcs1v15Sign, PublicKey, RsaPrivateKey, RsaPublicKey};
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
        Algorithm::RS256 => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS384 => {
            let mut hasher = Sha384::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS512 => {
            let mut hasher = Sha512::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.as_slice().to_vec()
        }
        _ => unimplemented!(),
    };

    // get signature scheme
    let signatures_scheme = match alg {
        Algorithm::RS256 => Pkcs1v15Sign::new::<Sha256>(),
        Algorithm::RS384 => Pkcs1v15Sign::new::<Sha384>(),
        Algorithm::RS512 => Pkcs1v15Sign::new::<Sha512>(),
        _ => unimplemented!(),
    };

    Ok(b64_encode(&key.sign(signatures_scheme, &digest).unwrap()))
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
        Algorithm::RS256 => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS384 => {
            let mut hasher = Sha384::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        Algorithm::RS512 => {
            let mut hasher = Sha512::new();
            hasher.update(message.as_bytes());
            let d = hasher.finalize();
            d.iter().copied().collect()
        }
        _ => unimplemented!(),
    };

    let signatures_scheme = match alg {
        Algorithm::RS256 => Pkcs1v15Sign::new::<Sha256>(),
        Algorithm::RS384 => Pkcs1v15Sign::new::<Sha384>(),
        Algorithm::RS512 => Pkcs1v15Sign::new::<Sha512>(),
        _ => unimplemented!(),
    };

    let signature_bytes = b64_decode(signature)?;

    key.verify(signatures_scheme, &digest, &signature_bytes)
        .map_err(|_| errors::new_error(ErrorKind::InvalidSignature))?;

    Ok(true)
}
