use std::convert::{TryFrom, TryInto};
// use std::time::Duration;

use crate::{dangerous_insecure_decode_with_validation, decode, decode_header};
use crate::{errors::new_error, Algorithm, DecodingKey, TokenData, Validation};
use serde::{self, de::DeserializeOwned, Deserialize, Serialize};

use crate::errors::{Error, ErrorKind, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWK {
    pub kty: JsonWebKeyTypes,
    pub alg: Option<Algorithm>,
    pub kid: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<JwkPublicKeyUse>,

    pub e: Option<String>,
    pub n: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWKS {
    keys: Vec<JWK>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum JsonWebKeyTypes {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "EC")]
    Ec,
    #[serde(rename = "oct")]
    OctetSeq,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum JwkPublicKeyUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

#[derive(Clone, Debug)]
pub struct JWKDecodingKey {
    pub alg: Option<Algorithm>,
    pub kid: Option<String>,
    pub key: DecodingKey,
}

impl JWKDecodingKey {
    pub fn new(kid: Option<String>, alg: Option<Algorithm>, key: DecodingKey) -> JWKDecodingKey {
        JWKDecodingKey { alg, kid, key }
    }

    pub fn new_rsa(
        kid: std::option::Option<String>,
        alg: Option<Algorithm>,
        n: &str,
        e: &str,
    ) -> Result<JWKDecodingKey> {
        Ok(JWKDecodingKey { alg, kid, key: DecodingKey::from_rsa_components(n, e)? })
    }

    pub fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }
}

impl TryFrom<JWK> for JWKDecodingKey {
    type Error = Error;

    fn try_from(JWK { kid, alg, kty, key_use: _, n, e }: JWK) -> Result<JWKDecodingKey> {
        let key = match (kty, n, e) {
            (JsonWebKeyTypes::Rsa, Some(n), Some(e)) => {
                JWKDecodingKey::new(kid, alg, DecodingKey::from_rsa_components(&n, &e)?)
            }
            (JsonWebKeyTypes::Rsa, _, _) => return Err(new_error(ErrorKind::InvalidRsaKey)),
            (_, _, _) => return Err(new_error(ErrorKind::UnsupportedKeyType)),
        };
        Ok(key)
    }
}

#[derive(Clone)]
pub struct JWKDecodingKeySet {
    pub(crate) keys: Vec<JWKDecodingKey>,
}

impl TryFrom<JWKS> for JWKDecodingKeySet {
    type Error = Error;

    fn try_from(jwks: JWKS) -> Result<Self> {
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
    pub fn keys_by_id(&self, kid: String) -> Vec<JWKDecodingKey> {
        self.keys.iter().filter(|k| k.kid == Some(kid.clone())).cloned().collect()
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    pub fn add_key(&mut self, key: JWKDecodingKey) {
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
        .filter(|key| if let Some(alg) = key.alg { alg == header.alg } else { true })
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
    use serde::{Serialize, Deserialize};

    use crate::{jwk::{JWKDecodingKeySet, JWKS, JWKDecodingKey}, Algorithm};

    #[derive(Serialize, Deserialize)]
    struct RsaComponents {
        E: String,
        N: String,
    }

    #[test]
    fn test_from_json() {
        let jwks: JWKS = serde_json::from_str(include_str!("../tests/jwk/test-jwks.json")).unwrap();
        assert_eq!(jwks.keys.len(), 2);
        let key_set: JWKDecodingKeySet = jwks.try_into().unwrap();
        assert_eq!(key_set.keys.len(), 1);
    }

    #[test]
    fn test_add_key() {
        let exponents: RsaComponents = serde_json::from_str(include_str!("../tests/jwk/rsa-components.json")).unwrap();
        let key = JWKDecodingKey::new_rsa(
            Some("1".into()),
            Some(Algorithm::RS256),
            &exponents.N,
            &exponents.E,
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
