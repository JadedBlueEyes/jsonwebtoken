// use ring::{rand, signature};
use crate::errors;
use crate::errors::{ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};
use ::rsa::{hash::Hash, padding::PaddingScheme};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The actual RSA signing + encoding
/// The key needs to be in binary DER-encoded ASN.1 format
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
pub(crate) fn sign(alg: PaddingScheme, key: &RsaPrivateKey, message: &str) -> Result<String> {
    let digest: Vec<u8> = match alg {
        // PaddingScheme::OAEP {digest, ..} => {
        //     digest.update(message.as_bytes());
        //     digest.finalize_reset()
        // },
        PaddingScheme::PKCS1v15Sign { hash } => match hash {
            None => message.as_bytes().into(),
            Some(Hash::SHA2_256) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            Some(Hash::SHA2_384) => {
                let mut hasher = Sha384::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            Some(Hash::SHA2_512) => {
                let mut hasher = Sha512::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    };

    Ok(b64_encode(&key.sign(alg, &digest).unwrap()))
}

/// Checks that a signature is valid based on the (n, e) RSA pubkey components
pub(crate) fn verify(
    alg: PaddingScheme,
    signature: &str,
    message: &str,
    key: &RsaPublicKey,
) -> Result<bool> {
    let digest: Vec<u8> = match alg {
        // PaddingScheme::OAEP {digest, ..} => {
        //     digest.update(message.as_bytes());
        //     digest.finalize_reset()
        // },
        PaddingScheme::PKCS1v15Sign { hash } => match hash {
            None => message.as_bytes().into(),
            Some(Hash::SHA2_256) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            Some(Hash::SHA2_384) => {
                let mut hasher = Sha384::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            Some(Hash::SHA2_512) => {
                let mut hasher = Sha512::new();
                hasher.update(message.as_bytes());
                let d = hasher.finalize();
                d.iter().copied().collect()
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    };
    let signature_bytes = b64_decode(signature)?;
    key.verify(alg, &digest, &signature_bytes)
        .map_err(|_| errors::new_error(ErrorKind::InvalidSignature))?;
    Ok(true)
}
