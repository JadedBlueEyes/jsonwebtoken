use std::convert::{TryFrom, TryInto};
// use std::time::Duration;

use crate::{dangerous_insecure_decode_with_validation, decode, decode_header};
use crate::{errors::new_error, Algorithm, DecodingKey, TokenData, Validation};
use serde::{self, de::DeserializeOwned, Deserialize};

use crate::errors::{Error, ErrorKind, Result};

use crate::registries::{JsonWebKeyType, Jwk, JwkSet};

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Jwk")]
pub struct JwkDecodingKey {
    pub alg: Option<Algorithm>,
    pub kid: Option<String>,
    pub key: DecodingKey,
}

impl JwkDecodingKey {
    pub fn new(kid: Option<String>, alg: Option<Algorithm>, key: DecodingKey) -> JwkDecodingKey {
        JwkDecodingKey { alg, kid, key }
    }

    pub fn new_rsa(
        kid: std::option::Option<String>,
        alg: Option<Algorithm>,
        n: &str,
        e: &str,
    ) -> Result<JwkDecodingKey> {
        Ok(JwkDecodingKey { alg, kid, key: DecodingKey::from_rsa_components(n, e)? })
    }

    pub fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }
}

impl TryFrom<Jwk> for JwkDecodingKey {
    type Error = Error;
    fn try_from(source: Jwk) -> Result<JwkDecodingKey> {
        let key = match source.kty {
            JsonWebKeyType::Rsa { n: Some(n), e: Some(e), .. } => JwkDecodingKey::new(
                source.kid,
                source.alg,
                DecodingKey::from_rsa_components(&n, &e)?,
            ),
            JsonWebKeyType::Rsa { .. } => return Err(new_error(ErrorKind::InvalidRsaKey)),
            _ => return Err(new_error(ErrorKind::UnsupportedKeyType)),
        };
        Ok(key)
    }
}

#[derive(Clone)]
pub struct JWKDecodingKeySet {
    pub(crate) keys: Vec<JwkDecodingKey>,
}

impl TryFrom<JwkSet> for JWKDecodingKeySet {
    type Error = Error;

    fn try_from(jwks: JwkSet) -> Result<Self> {
        let mut ks: JWKDecodingKeySet = JWKDecodingKeySet::new();
        for key in jwks.keys.iter() {
            if let Ok(k) = key.clone().try_into() {
                ks.add_key(k);
            }
        }
        Ok(ks)
    }
}

#[allow(dead_code)]
impl JWKDecodingKeySet {
    pub fn new() -> JWKDecodingKeySet {
        JWKDecodingKeySet { keys: Vec::new() }
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    /// Fetch a key by key id (KID)
    pub fn keys_by_id(&self, kid: String) -> Vec<JwkDecodingKey> {
        self.keys.iter().filter(|k| k.kid == Some(kid.clone())).cloned().collect()
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    pub fn add_key(&mut self, key: JwkDecodingKey) {
        self.keys.push(key);
    }

    /// Verify a JWT token.
    /// If the token is valid, it is returned.
    ///
    /// A token is considered valid if:
    /// * Is well formed
    /// * Has a `kid` field that matches a public signature `kid
    /// * Signature matches public key
    /// * It is not expired
    /// * The `nbf` is not set to before now
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<TokenData<T>> {
        let _ = dangerous_insecure_decode_with_validation::<serde_json::Value>(token, validation)?;
        let header = decode_header(token)?;
        // println!("{:?}", self.keys_by_id(header.kid.clone().unwrap()));
        // println!("{:?}", self.keys_by_id(header.kid.clone().unwrap()).iter().filter(|key| {if let Some(alg) = key.alg {
        //     alg == header.alg
        // } else {true}}));
        // println!("{:?}", self.keys_by_id(header.kid.clone().unwrap()).iter().filter(|key| {if let Some(alg) = key.alg {
        //     alg == header.alg
        // } else {true}}).find_map(|key| {Some(decode::<serde_json::Value>(token, &key.key, &validation).unwrap())}));
        let data = if let Some(ref kid) = header.kid {
            self.keys_by_id(kid.clone())
        } else {
            self.keys.clone()
        }
        .iter()
        .filter(|key| {
            if let (Some(alg), Some(header_alg)) = (key.alg, header.alg) {
                alg == header_alg
            } else {
                // If alg is not set, pass, otherwise fail.
                !matches!(key.alg, Some(_))
            }
        })
        .find_map(|key| decode(token, &key.key, validation).ok())
        .ok_or(new_error(ErrorKind::NoWorkingKey))?;

        Ok(data)
    }
}

impl Default for JWKDecodingKeySet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{
        jwk::{JWKDecodingKeySet, JwkDecodingKey},
        registries::JwkSet,
        Algorithm,
    };

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    struct RsaComponents {
        e: String,
        n: String,
    }

    #[test]
    fn test_from_json() {
        let jwks: JwkSet =
            serde_json::from_str(include_str!("../tests/jwk/test-jwks.json")).unwrap();
        assert_eq!(jwks.keys.len(), 2);
        let key_set: JWKDecodingKeySet = jwks.try_into().unwrap();
        assert_eq!(key_set.keys.len(), 1);
    }

    #[test]
    fn test_add_key() {
        let exponents: RsaComponents =
            serde_json::from_str(include_str!("../tests/jwk/rsa-components.json")).unwrap();
        let key = JwkDecodingKey::new_rsa(
            Some("1".into()),
            Some(Algorithm::RS256),
            &exponents.n,
            &exponents.e,
        );

        let mut key_set = JWKDecodingKeySet::new();

        assert_eq!(0usize, key_set.keys.len());

        key_set.add_key(key.unwrap());

        assert_eq!(1usize, key_set.keys_len());

        // Is the key reachable by ID?

        let result = key_set.keys_by_id("1".into());

        assert!(!result.is_empty());

        let result = key_set.keys_by_id("2".into());

        assert!(result.is_empty());
    }
}
