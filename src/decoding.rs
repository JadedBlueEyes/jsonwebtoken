use rsa::RsaPublicKey;
use serde::de::DeserializeOwned;

use crate::crypto::verify;
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
// use crate::pem::decoder::PemEncodedKey;
use crate::serialization::from_jwt_part_claims;
use crate::validation::{validate, Validation};

use base64::{engine::general_purpose::STANDARD, Engine};
/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

/// All the different kind of keys we can use to decode a JWT
/// This key can be re-used so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub enum DecodingKey {
    Hmac(Vec<u8>),
    Rsa(rsa::RsaPublicKey),
    // EcPkcs8(Vec<u8>),
}

impl DecodingKey {
    /// If you're using HMAC, use this.
    pub fn from_hmac_secret(secret: &[u8]) -> Self {
        DecodingKey::Hmac(secret.to_vec())
    }

    /// If you're using HMAC with a base64 encoded, use this.
    pub fn from_base64_hmac_secret(secret: &str) -> Result<Self> {
        Ok(DecodingKey::Hmac(STANDARD.decode(secret)?))
    }

    pub fn from_rsa(key: rsa::RsaPublicKey) -> Result<Self> {
        Ok(DecodingKey::Rsa(key))
    }

    /// Convenience function for JWKS implementors
    pub fn from_rsa_components(n: &str, e: &str) -> Result<Self> {
        use crate::serialization::b64_decode;
        let n = rsa::BigUint::from_bytes_be(&b64_decode(n)?);
        let e = rsa::BigUint::from_bytes_be(&b64_decode(e)?);
        Ok(DecodingKey::Rsa(
            RsaPublicKey::new(n, e).map_err(|_| new_error(ErrorKind::InvalidKeyFormat))?,
        ))
    }
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken_rustcrypto::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_hmac_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !validation.algorithms.is_empty() & !&validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if !verify(signature, message, key, header.alg)? {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a JWT without any signature verification/validations.
///
/// NOTE: Do not use this unless you know what you are doing! If the token's signature is invalid, it will *not* return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken_rustcrypto::{dangerous_insecure_decode, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = dangerous_insecure_decode::<Claims>(&token);
/// ```
pub fn dangerous_insecure_decode<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    let (decoded_claims, _): (T, _) = from_jwt_part_claims(claims)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode and validate a JWT without any signature verification.
///
/// If the token is invalid or the claims fail validation, it will return an error.
///
/// NOTE: Do not use this unless you know what you are doing! If the token's signature is invalid, it will *not* return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken_rustcrypto::{dangerous_insecure_decode_with_validation, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token";
/// // Claims is a struct that implements Deserialize
/// let token_message = dangerous_insecure_decode_with_validation::<Claims>(&token, &Validation::new(Algorithm::HS256));
/// ```
pub fn dangerous_insecure_decode_with_validation<T: DeserializeOwned>(
    token: &str,
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !validation.algorithms.is_empty() & !&validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a JWT without any signature verification/validations. DEPRECATED.
#[deprecated(
    note = "This function has been renamed to `dangerous_insecure_decode` and will be removed in a later version."
)]
pub fn dangerous_unsafe_decode<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>> {
    dangerous_insecure_decode(token)
}

/// Decode a JWT without any signature verification/validations and return its [Header](struct.Header.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken_rustcrypto::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(message.rsplitn(2, '.'));
    Header::from_encoded(header)
}
