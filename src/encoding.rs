use serde::ser::Serialize;

use crate::crypto;
use crate::errors::Result;
use crate::header::Header;
// use crate::pem::decoder::PemEncodedKey;
use crate::serialization::b64_encode_part;

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub enum EncodingKey {
    Hmac(Vec<u8>),
    Rsa(Box<rsa::RsaPrivateKey>),
    // EcPkcs8(Vec<u8>),
}

impl EncodingKey {
    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_hmac_secret(secret: &[u8]) -> Self {
        EncodingKey::Hmac(secret.to_vec())
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_hmac_secret(secret: &str) -> Result<Self> {
        Ok(EncodingKey::Hmac(base64::decode(&secret)?))
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
/// use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
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
/// let token = encode(&Header::default(), &my_claims, &EncodingKey::from_hmac_secret("secret".as_ref())).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &EncodingKey) -> Result<String> {
    let _ = crypto::validate_matching_key(key, header.alg)?;
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = crypto::sign(&*message, key, header.alg)?;

    Ok([message, signature].join("."))
}
