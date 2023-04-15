use serde::ser::Serialize;

use crate::errors::Result;
use crate::headers::JwtHeader;
use crate::{crypto, errors::ErrorKind};
// use crate::pem::decoder::PemEncodedKey;
use crate::serialization::b64_encode_part;

use base64::{engine::general_purpose::STANDARD, Engine};

/// A key to encode a JWT with. Can be nothing, a secret or an RSA private key
/// This key can be re-used - so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub enum EncodingKey {
    None,
    OctetSeq(Vec<u8>),
    Rsa(Box<rsa::RsaPrivateKey>),
    // Ec
    // OctetStringPairs
}

impl EncodingKey {
    pub fn from_none() -> Self {
        EncodingKey::None
    }

    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey::OctetSeq(secret.to_vec())
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        Ok(EncodingKey::OctetSeq(STANDARD.decode(secret)?))
    }

    pub fn from_rsa(key: rsa::RsaPrivateKey) -> Result<Self> {
        Ok(EncodingKey::Rsa(Box::new(key)))
    }
}

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key.
/// If the algorithm given is RSA or EC, the key needs to be in the PEM format.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken_rustcrypto::{encode, Algorithm, headers::JwtHeader, EncodingKey};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let token = encode(&JwtHeader::new(Algorithm::HS256), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &JwtHeader, claims: &T, key: &EncodingKey) -> Result<String> {
    let alg = header.general_headers.alg.ok_or(ErrorKind::InvalidAlgorithm)?;
    crypto::validate_matching_key(key, alg)?;
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

    let signature = crypto::sign(&message, key, alg)?;
    if let Some(sig) = signature {
        Ok([message, sig].join("."))
    } else {
        Ok([&message, "."].concat())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_none_has_empty_sig() {
        let key = super::EncodingKey::from_none();
        let token =
            super::encode(&super::JwtHeader::new(crate::Algorithm::None), &(), &key).unwrap();
        assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.bnVsbA.");
    }
}
