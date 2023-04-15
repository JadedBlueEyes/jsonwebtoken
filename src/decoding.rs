use rsa::RsaPublicKey;
use serde::de::DeserializeOwned;

use crate::crypto::verify;
use crate::errors::{new_error, ErrorKind, Result};
use crate::{headers::JwtHeader, Algorithm};
// use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_decode, from_jwt_part_claims};
use crate::validation::{validate, Validation};

use base64::{engine::general_purpose::STANDARD, Engine};

/// Converts an encoded part into the Header struct if possible
pub(crate) fn from_encoded(encoded_part: &str) -> Result<JwtHeader> {
    let decoded = b64_decode(encoded_part)?;
    let s = String::from_utf8(decoded)?;

    Ok(serde_json::from_str(&s)?)
}

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: JwtHeader,
    /// The decoded JWT claims
    /// Note: see <https://www.iana.org/assignments/jwt/jwt.xhtml#claims> for many of the properties that you might encounter.
    pub claims: T,
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two_or_three {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), third) => (first, second, third),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

/// All the different kind of keys we can use to decode a JWT
/// This key can be re-used so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub enum DecodingKey {
    None,
    OctetSeq(Vec<u8>),
    Rsa(rsa::RsaPublicKey),
    // Ec
    // OctetStringPairs
}

impl DecodingKey {
    pub fn from_none() -> Self {
        DecodingKey::None
    }
    pub fn is_none(&self) -> bool {
        self == &DecodingKey::None
    }
    /// If you're using HMAC, use this.
    pub fn from_secret(secret: &[u8]) -> Self {
        DecodingKey::OctetSeq(secret.to_vec())
    }

    /// If you're using HMAC with a base64 encoded, use this.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        Ok(DecodingKey::OctetSeq(STANDARD.decode(secret)?))
    }

    pub fn from_rsa(key: rsa::RsaPublicKey) -> Result<Self> {
        Ok(DecodingKey::Rsa(key))
    }

    /// Convenience function for JWKS implementors
    pub fn from_rsa_components(n: &str, e: &str) -> Result<Self> {
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
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (header, claims, signature) = expect_two_or_three!(token.splitn(3, '.'));
    let header_decoded: JwtHeader = from_encoded(header)?;

    let alg = header_decoded.general_headers.alg.ok_or(ErrorKind::InvalidAlgorithm)?;

    if !validation.algorithms.is_empty() & !&validation.algorithms.contains(&alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if (alg == Algorithm::None) & (key.is_none()) {
    } else if let Some(signature) = signature {
        if !verify(signature, &[header, claims].join("."), key, alg)? {
            return Err(new_error(ErrorKind::InvalidSignature));
        }
    } else {
        return Err(new_error(ErrorKind::MissingSignature));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header: header_decoded, claims: decoded_claims })
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
    let (header, claims, _) = expect_two_or_three!(token.splitn(3, '.'));
    let header: JwtHeader = from_encoded(header)?;

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
    let (header, claims, _) = expect_two_or_three!(token.splitn(3, '.'));
    let header: JwtHeader = from_encoded(header)?;
    let alg = header.general_headers.alg.ok_or(ErrorKind::InvalidAlgorithm)?;

    if !validation.algorithms.is_empty() & !&validation.algorithms.contains(&alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a JWT without any signature verification/validations and return its [JwtHeader](struct.JwtHeader.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken_rustcrypto::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<JwtHeader> {
    let (header, _, _) = expect_two_or_three!(token.splitn(2, '.'));
    let dec: JwtHeader = from_encoded(header)?;
    Ok(dec)
}
