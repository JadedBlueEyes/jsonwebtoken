use hmac::{Hmac, Mac};

use crate::algorithms::Algorithm;
use crate::decoding::DecodingKey;
use crate::encoding::EncodingKey;
use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};

use sha2::{Sha256, Sha384, Sha512};
// pub(crate) mod ecdsa;
pub(crate) mod rsa;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;
/// The actual HS signing + encoding
/// Could be in its own file to match RSA/EC but it's 2 lines...
pub(crate) fn sign_hmac(alg: Algorithm, key: &[u8], message: &str) -> Result<String> {
    // println!("alg: {:?}\nkey: {:?}\nmessage: {:?}");

    // let digest = hmac::sign(&hmac::Key::new(alg, key), message.as_bytes());
    let digest = match alg {
        Algorithm::HS256 => {
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(message.as_bytes());
            b64_encode(mac.finalize().into_bytes().as_slice())
        }
        Algorithm::HS384 => {
            let mut mac = HmacSha384::new_from_slice(key).unwrap();
            mac.update(message.as_bytes());
            b64_encode(mac.finalize().into_bytes().as_slice())
        }
        Algorithm::HS512 => {
            let mut mac = HmacSha512::new_from_slice(key).unwrap();
            mac.update(message.as_bytes());
            b64_encode(mac.finalize().into_bytes().as_slice())
        }
        _ => unreachable!(),
    };
    Ok(digest)
}

/// Validates that the key can be used with the given algorithm
pub fn validate_matching_key(key: &EncodingKey, algorithm: Algorithm) -> Result<()> {
    match key {
        EncodingKey::Hmac(_) => match algorithm {
            Algorithm::HS256 => Ok(()),
            Algorithm::HS384 => Ok(()),
            Algorithm::HS512 => Ok(()),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },
        EncodingKey::Rsa(_) => match algorithm {
            Algorithm::RS256
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::RS384
            | Algorithm::RS512 => Ok(()),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },
        // EncodingKey::EcPkcs8(_)
        //     => match algorithm {
        //         Algorithm::ES256 | Algorithm::ES384 => Ok(()),
        //         _ => Err(ErrorKind::InvalidAlgorithm.into())
        //     }
    }
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &str, key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    match key {
        EncodingKey::Hmac(s) => match algorithm {
            Algorithm::HS256 => sign_hmac(Algorithm::HS256, s, message),
            Algorithm::HS384 => sign_hmac(Algorithm::HS384, s, message),
            Algorithm::HS512 => sign_hmac(Algorithm::HS512, s, message),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },

        EncodingKey::Rsa(k) => match algorithm {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => rsa::sign(algorithm, k, message),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },
        // EncodingKey::EcPkcs8(k)
        //     => match algorithm {
        //         Algorithm::ES256 | Algorithm::ES384 => {
        //             ecdsa::sign_pkcs8(ecdsa::alg_to_ec_signing(algorithm), k, message)
        //         },
        //         _ => Err(ErrorKind::InvalidAlgorithm.into())
        //     }
    }
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    message: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    match key {
        DecodingKey::Hmac(s) => match algorithm {
            Algorithm::HS256 => {
                let mut mac = HmacSha256::new_from_slice(s).unwrap();
                mac.update(message.as_bytes());
                Ok(mac.finalize().into_bytes().as_slice()
                    == b64_decode(signature)
                        .map_err(|_e| new_error(ErrorKind::InvalidSignature))?)
            }
            Algorithm::HS384 => {
                let mut mac = HmacSha384::new_from_slice(s).unwrap();
                mac.update(message.as_bytes());
                Ok(mac.finalize().into_bytes().as_slice()
                    == b64_decode(signature)
                        .map_err(|_e| new_error(ErrorKind::InvalidSignature))?)
            }
            Algorithm::HS512 => {
                let mut mac = HmacSha512::new_from_slice(s).unwrap();
                mac.update(message.as_bytes());
                Ok(mac.finalize().into_bytes().as_slice()
                    == b64_decode(signature)
                        .map_err(|_e| new_error(ErrorKind::InvalidSignature))?)
            }
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },
        DecodingKey::Rsa(k) => match algorithm {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => rsa::verify(algorithm, signature, message, k),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        },
    }
}
