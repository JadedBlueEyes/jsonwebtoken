use std::convert::{TryFrom, TryInto};
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use regex::Regex;

use reqwest::Response;
use serde::{self, de::DeserializeOwned, Deserialize, Serialize};

use crate::error::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWK {
    pub kty: JsonWebKeyTypes,
    pub alg: Option<jsonwebtoken::Algorithm>,
    pub kid: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<JwkPublicKeyUse>,

    pub e: Option<String>,
    pub n: Option<String>,
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
pub struct JwtKey {
    pub alg: jsonwebtoken::Algorithm,
    pub kid: String,
    pub kind: JwtKeyKind,
}
#[derive(Debug, Clone)]
pub enum JwtKeyKind {
    RSA(DecodingKey),
    UnsupportedKty(JsonWebKeyTypes),
}

impl JwtKey {
    pub fn new(kid: &str, alg: Algorithm, key: DecodingKey) -> JwtKey {
        JwtKey {
            alg,
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(key),
        }
    }

    pub fn new_rsa256(kid: &str, n: &str, e: &str) -> Result<JwtKey, jsonwebtoken::errors::Error> {
        Ok(JwtKey {
            alg: Algorithm::RS256,
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(DecodingKey::from_rsa_components(n, e)?),
        })
    }
    pub fn new_rsa512(kid: &str, n: &str, e: &str) -> Result<JwtKey, jsonwebtoken::errors::Error> {
        Ok(JwtKey {
            alg: Algorithm::RS512,
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(DecodingKey::from_rsa_components(n, e)?),
        })
    }

    pub fn decoding_key(&self) -> Result<&DecodingKey, Error> {
        match &self.kind {
            JwtKeyKind::RSA(key) => Ok(key),
            JwtKeyKind::UnsupportedKty(kty) => Err(err("Unsupported key type", ErrorKind::UnsupportedKeyType(*kty))),
        }
    }
}

impl TryFrom<JWK> for JwtKey {
    type Error = Error;

    fn try_from(JWK { kid, alg, kty, key_use, n, e }: JWK) -> Result<Self, Error> {
        let kid = kid.ok_or(Error {
            msg: "No key ID was specified in the JWK",
            kind: ErrorKind::NoKeyId,
        })?;
        let alg = alg.ok_or(Error {
            msg: "No algorithm was specified in the JWK",
            kind: ErrorKind::NoAlgorithm,
        })?;
        let kind = match (kty, n, e) {
            (JsonWebKeyTypes::Rsa, Some(n), Some(e)) => JwtKeyKind::RSA(DecodingKey::from_rsa_components(&n, &e).map_err(|x| Error {
                msg: "Failed to construct RSA public key",
                kind: ErrorKind::JwtDecodeError(Box::new(x.into_kind())),
            })?),
            (JsonWebKeyTypes::Rsa, _, _) => return Err(err("RSA key misses parameters", ErrorKind::Key)),
            (_, _, _) => JwtKeyKind::UnsupportedKty(kty),
        };
        Ok(JwtKey { alg, kid, kind })
    }
}

#[derive(Clone)]
pub struct KeyStore {
    pub(crate) key_url: Option<String>,
    pub(crate) keys: Vec<JwtKey>,
}

pub static KEY_CACHE: ::cached::once_cell::sync::Lazy<::cached::async_mutex::Mutex<crate::cache::ExpiringCache<String, Vec<JWK>>>> =
    ::cached::once_cell::sync::Lazy::new(|| ::cached::async_mutex::Mutex::new(crate::cache::ExpiringCache::with_lifespan(Duration::from_secs(600))));

#[allow(dead_code)]
impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore { key_url: None, keys: Vec::new() }
    }

    pub async fn new_from(jkws_url: String) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore { key_url: Some(jkws_url), keys: Vec::new() };

        // key_store.key_url = jkws_url;

        key_store.reload_keys().await?;

        Ok(key_store)
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_url(&self) -> Option<&String> {
        self.key_url.as_ref()
    }

    async fn get_keys(url: &str) -> Result<Vec<JWK>, Error> {
        let key = (*url).to_string();
        {
            let mut cache = KEY_CACHE.lock().await;
            if let Some(result) = cache.cache_get(&key) {
                return Ok(result.clone());
            }
        }

        #[derive(Clone, Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JWK>,
        }

        let mut response = reqwest::get(url).await.map_err(|_| err_con("Could not download JWKS"))?;
        let max_age_result = KeyStore::cache_max_age(&mut response);
        let keys = response.json::<JwtKeys>().await.map_err(|_| err_int("Failed to parse keys"))?.keys;

        let duration;
        if let Ok(value) = max_age_result {
            duration = Duration::new(value, 0);
        } else {
            duration = Duration::new(600, 0);
        }

        let mut cache = KEY_CACHE.lock().await;
        cache.cache_set_with_lifespan(key, duration, keys.clone());

        Ok(keys)
    }

    pub async fn reload_keys(&mut self) -> Result<(), Error> {
        if self.key_url.is_none() {
            return Err(Error {
                msg: "No remote store specified to fetch from in key_url",
                kind: ErrorKind::NoRemoteStore,
            });
        }

        let keys = KeyStore::get_keys(self.key_url.as_ref().unwrap()).await?;

        for jwk in keys {
            self.add_key(&jwk.try_into()?);
        }

        Ok(())
    }

    fn cache_max_age(response: &mut Response) -> Result<u64, ()> {
        let header = response.headers().get("cache-control").ok_or(())?;

        let header_text = header.to_str().map_err(|_| ())?;

        let re = Regex::new("max-age\\s*=\\s*(\\d+)").map_err(|_| ())?;

        let captures = re.captures(header_text).ok_or(())?;

        let capture = captures.get(1).ok_or(())?;

        let text = capture.as_str();

        let value = text.parse::<u64>().map_err(|_| ())?;

        Ok(value)
    }

    /// Fetch a key by key id (KID)
    pub fn key_by_id(&self, kid: &str) -> Option<&JwtKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    pub fn add_key(&mut self, key: &JwtKey) {
        self.keys.push(key.clone());
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
    pub fn verify<T: DeserializeOwned>(&self, token: &str, validation: &Validation) -> Result<TokenData<T>, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(err_jwt)?;

        let kid = header.kid.ok_or_else(|| err_key("No key id"))?;

        let key = self.key_by_id(&kid).ok_or_else(|| err_key("JWT key does not exists"))?;

        if key.alg != header.alg {
            return Err(err("Token and its key have non-matching algorithms", ErrorKind::AlgorithmMismatch));
        }

        let data = jsonwebtoken::decode(token, key.decoding_key()?, &validation).map_err(err_jwt)?;

        Ok(data)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
