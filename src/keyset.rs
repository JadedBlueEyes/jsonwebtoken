use std::time::{Duration, SystemTime};

use base64::{decode_config, URL_SAFE_NO_PAD};
use regex::Regex;

use reqwest::Response;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::{
    de::DeserializeOwned,
    {Deserialize, Serialize},
};
use serde_json::Value;

use crate::error::*;
use crate::jwt::*;

type HeaderBody = String;
pub type Signature = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtKey {
    #[serde(default)] // https://github.com/jfbilodeau/jwks-client/issues/1
    pub e: String,
    pub kty: String,
    pub alg: String,
    #[serde(default)] // https://github.com/jfbilodeau/jwks-client/issues/1
    pub n: String,
    pub kid: String,
}

impl JwtKey {
    pub fn new(kid: &str, n: &str, e: &str) -> JwtKey {
        JwtKey {
            e: e.to_owned(),
            kty: "JTW".to_string(),
            alg: "RS256".to_string(),
            n: n.to_owned(),
            kid: kid.to_owned(),
        }
    }
}

impl Clone for JwtKey {
    fn clone(&self) -> Self {
        JwtKey {
            e: self.e.clone(),
            kty: self.kty.clone(),
            alg: self.alg.clone(),
            n: self.n.clone(),
            kid: self.kid.clone(),
        }
    }
}

#[derive(Clone)]
pub struct KeyStore {
    pub(crate) key_url: String,
    pub(crate) keys: Vec<JwtKey>,
}

pub static KEY_CACHE: ::cached::once_cell::sync::Lazy<
    ::cached::async_mutex::Mutex<crate::cache::ExpiringCache<String, Vec<JwtKey>>>,
> = ::cached::once_cell::sync::Lazy::new(|| {
    ::cached::async_mutex::Mutex::new(crate::cache::ExpiringCache::with_lifespan(Duration::from_secs(600)))
});

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore {
            key_url: "".to_owned(),
            keys: vec![],
        }
    }

    pub async fn new_from(jkws_url: String) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore::new();

        key_store.key_url = jkws_url;

        key_store.reload_keys().await?;

        Ok(key_store)
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_url(&self) -> &str {
        &self.key_url
    }

    async fn get_keys(url: &str) -> Result<Vec<JwtKey>, Error> {
        let key = (*url).to_string();
        {
            let mut cache = KEY_CACHE.lock().await;
            if let Some(result) = cache.cache_get(&key) {
                return Ok(result.clone());
            }
        }

        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JwtKey>,
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

        self.keys = KeyStore::get_keys(&self.key_url).await?;

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

    fn decode_segments(&self, token: &str) -> Result<(Header, Payload, Signature, HeaderBody), Error> {
        let raw_segments: Vec<&str> = token.split('.').collect();
        if raw_segments.len() != 3 {
            return Err(err_inv("JWT does not have 3 segments"));
        }

        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let signature_segment = raw_segments[2].to_string();

        let header = Header::new(decode_segment::<Value>(header_segment).map_err(|_| err_hea("Failed to decode header"))?);
        let payload = Payload::new(decode_segment::<Value>(payload_segment).map_err(|_| err_pay("Failed to decode payload"))?);

        let body = format!("{}.{}", header_segment, payload_segment);

        Ok((header, payload, signature_segment, body))
    }

    pub fn decode(&self, token: &str) -> Result<Jwt, Error> {
        let (header, payload, signature, _) = self.decode_segments(token)?;

        Ok(Jwt::new(header, payload, signature))
    }

    pub fn verify_time(&self, token: &str, time: SystemTime) -> Result<Jwt, Error> {
        let (header, payload, signature, body) = self.decode_segments(token)?;

        if header.alg() != Some("RS256") {
            return Err(err_inv("Unsupported algorithm"));
        }

        let kid = header.kid().ok_or_else(|| err_key("No key id"))?;

        let key = self.key_by_id(kid).ok_or_else(|| err_key("JWT key does not exists"))?;

        let e = decode_config(&key.e, URL_SAFE_NO_PAD).map_err(|_| err_cer("Failed to decode exponent"))?;
        let n = decode_config(&key.n, URL_SAFE_NO_PAD).map_err(|_| err_cer("Failed to decode modulus"))?;

        verify_signature(&e, &n, &body, &signature)?;

        let jwt = Jwt::new(header, payload, signature);

        if jwt.expired_time(time).unwrap_or(false) {
            return Err(err_exp("Token expired"));
        }
        if jwt.early_time(time).unwrap_or(false) {
            return Err(err_nbf("Too early to use token (nbf)"));
        }

        Ok(jwt)
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
    pub fn verify(&self, token: &str) -> Result<Jwt, Error> {
        self.verify_time(token, SystemTime::now())
    }

}

fn verify_signature(e: &[u8], n: &[u8], message: &str, signature: &str) -> Result<(), Error> {
    let pkc = RsaPublicKeyComponents { e, n };

    let message_bytes = &message.as_bytes().to_vec();
    let signature_bytes = decode_config(&signature, URL_SAFE_NO_PAD).map_err(|_| err_sig("Could not base64 decode signature"))?;

    let result = pkc.verify(&RSA_PKCS1_2048_8192_SHA256, &message_bytes, &signature_bytes);

    result.map_err(|_| err_cer("Signature does not match certificate"))
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = decode_config(segment, base64::URL_SAFE_NO_PAD).map_err(|_| err_inv("Failed to decode segment"))?;
    let slice = String::from_utf8_lossy(&raw);
    let decoded: T = serde_json::from_str(&slice).map_err(|_| err_inv("Failed to decode segment"))?;

    Ok(decoded)
}
