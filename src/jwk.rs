use std::convert::{TryFrom, TryInto};
use std::time::Duration;

use crate::{Algorithm, DecodingKey, TokenData, Validation, errors::new_error};
use crate::{decode_header, decode, dangerous_insecure_decode_with_validation};
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
    keys: Vec<JWK>
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
        JWKDecodingKey {
            alg,
            kid,
            key,
        }
    }

    pub fn new_rsa(kid: std::option::Option<String>, alg: Option<Algorithm>, n: &str, e: &str) -> Result<JWKDecodingKey> {
        Ok(JWKDecodingKey {
            alg,
            kid,
            key: DecodingKey::from_rsa_components(n, e)?,
        })
    }

    pub fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }
}

impl TryFrom<JWK> for JWKDecodingKey {
    type Error = Error;

    fn try_from(JWK { kid, alg, kty, key_use, n, e }: JWK) -> Result<JWKDecodingKey> {
        let key = match (kty, n, e) {
            (JsonWebKeyTypes::Rsa, Some(n), Some(e)) => JWKDecodingKey::new(kid, alg.clone(), DecodingKey::from_rsa_components(&n, &e)?),
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

impl<'a> TryFrom<JWKS> for JWKDecodingKeySet {
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
impl<'a> JWKDecodingKeySet {
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
    pub fn verify<T: DeserializeOwned>(&self, token: &str, validation: &Validation) -> Result<TokenData<T>> {
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
        }.iter().filter(|key| {if let Some(alg) = key.alg {
            alg == header.alg
        } else {true}}).find_map(|key| {decode(token, &key.key, &validation).ok()}).ok_or(new_error(ErrorKind::NoWorkingKey))?;
        

        Ok(data)
    }
}

impl<'a> Default for JWKDecodingKeySet {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Serialize};

    use crate::{Algorithm, jwk::{JWKDecodingKeySet, JWKS}};


    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3k3jgfWalvlaX
H/R7sJ2gpNjzG37fIxvLwGA11qBU2R4KRnilFuZBdFY0Luqf/9lrHH12fMdvMYK6
XlbREt93egHc8RLCytCH6iJdUQ9NiG9Q9CRfS8F8Jcm2D/NjaZjUPEo4iJednw9o
r/tLHRoya9H//RjLZrl0gBYKaM+zGf49wZk6RVSb4PlsfX5lK1wD/ryvhlI+LHtL
OGCXVGgdv1DolJ6TJmozRB/CGBvuytlVcL/3+bk8TH3AxU1ilgkGteEPkhCb1HMT
2glLxP4CL7j/mY1M1cjx/WutiB99ZLjB/1y+wSKGu8SD3zrsHZ/3wvu7H0uWV7uO
wcK3CBXXAgMBAAECggEBALCePOTXIYQDPXIGt4StZupgz64N3SG3uI1ul+IUjYs0
nPdL19UV1BBTaoCoRuoLENZBwd/Wq1Yqr1i5XROn8cIUa2hztBYfZUPumoNncq6o
vliHm9rnms7j2E7Gx+b0eKpxGwOLPzvSBdQ1xDL/W+342EFO86T2PyV7+jinoHTx
wN7aO5AygunyVW8CFoOFfZRFi8g9J4CkZ2HvGzAerMNz41UJc/pNa8Sl7E1Z3HWq
IHmahP8sVqo/zm/cDpivn6MZKBadASkvBf4TNJU5uZPdn37Rmwl4xVyNyNPCq3On
afSnvl1Z4XyESUQSi0L/EEkdDV7qgj1MhUHsUMy6SskCgYEA8A+X9dk11TjGBki1
ulThRteKNGTdweRk6ZiR7dV7+Oq4W8yYrX95f2byxVrFKUhxV5BIYyOtcpqa5FGc
AXcczpJQ9lUCEqQrQp/JXk4yZrwsQd63PHei72pgp6iZVHhtBJXedWsx3B8fLsz4
YaE3laTF4OQY6iLH0TDizMKsb4sCgYEAw8PIvzFnLsCNDXfNLxfHu8m4xRaNO4Qn
q8laJpwL9AIKKnFaKOdmEY0fuyh+YRcBmgSc1OMSOspAguHBRYB7RO0+Q6Qswa/L
+ra8HTol0Gu021NF81t7fT4tWww/PRDNoobpvkt9xc7t6cCljq6ysP9qKiaO6YvD
6BVHTDgCvGUCgYBQMoVrpmLrlonhM40ycITJ69vJ4SCMU8a6mzO1JqrB33gzgshG
vd1TCIt2Dvrq7b6fqB3msNaTAL9aI0Fg4/AFuq+9e2yz2ZByM3tMPAdudtK6NrM0
SitunDUqDZMbuxeAfqjQxTzk8qiyM9uOkhNFtMQ+ezUvkur6IcDC8w40PQKBgBnO
MiU53u8jxLQ0yaBekx6m/atFSMLCrfQQK8kRIuY8apijro3byvGfV8J1GQu1W6mw
1/ecIygKxyw5lB+USyuP1nhWKOwzP0FCW1PC+X8a45FRzdPBiGq/Cn2JBMEI+QJm
pGNIUkEEAQqiMXC4iKeaU6VQxd/1Y5KxU1+xtnKdAoGBAJIWLnvxcMbF1JNft9Li
vQlvs/dWpK19XvDXENyEmQQQcYkq35GbtxPDXiRvFrQbr44DwHS7EXthATsl03Ow
G0nSkIxiRIJNXp6mst6C6hMWzgWV4GBcTUWSw2WhKojwGVRfZgU0d2awSI0YtsT4
Ko5K8hGLY0C471Wy9yWk+hAI
-----END PRIVATE KEY-----
";

    fn valid_token() -> String {
        let mut claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(TEST_CLAIMS).unwrap();
        claims["exp"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10).into();

        encode_token(claims)
    }
    fn early_token() -> String {
        let mut claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(TEST_CLAIMS).unwrap();
        claims["nbf"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 100).into();
        claims["exp"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 200).into();

        encode_token(claims)
    }
    fn expired_token() -> String {
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(TEST_CLAIMS).unwrap();

        encode_token(claims)
    }
    fn encode_token(claims: serde_json::Map<String, serde_json::Value>) -> String {
        let key = crate::EncodingKey::from_rsa(rsa::RSAPrivateKey::from_pkcs8(&pem_to_der(PRIVATE_KEY)).unwrap()).unwrap();
        let mut header = crate::Header::new(crate::Algorithm::RS256);
        header.kid = Some("1".to_owned());
        crate::encode(&header, &claims, &key).unwrap()
    }
    fn pem_to_der(pem: &str) -> Vec<u8> {
        base64::decode(pem.split('\n').filter(|line| !line.starts_with('-')).fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        }))
        .unwrap()
    }

    pub const TEST_CLAIMS: &str = r#"
    {
        "name": "Ada Lovelace",
        "iss": "https://example.com/test",
        "aud": "test",
        "auth_time": 100,
        "user_id": "uid123",
        "sub": "sbu123",
        "iat": 200,
        "exp": 500,
        "nbf": 300,
        "email": "alovelace@example.com"
    }"#;
    pub const KEY_URL: &str = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.8/test/test-jwks.json";
    pub const E: &str = "AQAB";
    pub const N: &str = "t5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w";
    pub const N_INVALID: &str = "xt5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w==";
    // pub const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";
    pub const INV_CERT: &str = ".XXXeTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TestPayload {
        pub iss: String,
        pub name: String,
        pub email: String,
    }

    #[derive(Deserialize, Debug)]
    struct TestClaims {
        iss: String,
        name: String,
        email: String,
    }

    #[test]
    fn test_from_json() {
        use std::convert::TryInto;
        let jwks: JWKS = reqwest::blocking::get(KEY_URL).unwrap().json().unwrap();
        assert_eq!(jwks.keys.len(), 2);
        let key_set: JWKDecodingKeySet = jwks.try_into().unwrap();
        assert_eq!(key_set.keys.len(), 1);
    }


    #[test]
    fn test_add_key() {
        let key = crate::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), N, E);

        let mut key_set = JWKDecodingKeySet::new();

        assert_eq!(0usize, key_set.keys_len());

        key_set.add_key(key.unwrap());

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.keys_by_id("1".into());

        assert!(!result.is_empty());
    }

    #[test]
    fn test_get_key() {
        let key = crate::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), N, E);

        let mut key_set = JWKDecodingKeySet::new();

        assert_eq!(0usize, key_set.keys.len());

        key_set.add_key(key.unwrap());

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.keys_by_id("1".into());

        assert!(!result.is_empty());

        let result = key_set.keys_by_id("2".into());

        assert!(result.is_empty());
    }

    #[test]
    fn test_verify() {
        let key = crate::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), N, E);

        let mut key_set = JWKDecodingKeySet::new();

        key_set.add_key(key.unwrap());

        let validation = crate::Validation {
            validate_nbf: true,
            validate_exp: true,
            algorithms: vec![crate::Algorithm::RS256],
            leeway: 15,
            sub: None,
            aud: None,
            iss: Some("https://example.com/test".to_owned()),
        };

        let result: Result<crate::TokenData<TestClaims>, _> = key_set.verify(&valid_token(), &validation);

        assert!(result.is_ok(), "{:?}", result);

        let jwt = result.unwrap();

        assert_eq!("https://example.com/test", jwt.claims.iss);
        assert_eq!("Ada Lovelace", jwt.claims.name);
        assert_eq!("alovelace@example.com", jwt.claims.email);

        let result: Result<crate::TokenData<TestClaims>, _> = key_set.verify(&early_token(), &validation); // early

        assert_eq!(format!("{:?}", result), r#"Err(Error(ImmatureSignature))"#);

        let result: Result<crate::TokenData<TestClaims>, _> = key_set.verify(&expired_token(), &validation); // late

        assert_eq!(format!("{:?}", result), r#"Err(Error(ExpiredSignature))"#);
    }

    #[test]
    #[should_panic(expected = "NoWorkingKey")]
    fn test_verify_invalid_certificate() {
        let key = crate::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), N, E);

        let mut key_set = JWKDecodingKeySet::new();

        key_set.add_key(key.unwrap());

        let validation = crate::Validation {
            validate_nbf: true,
            validate_exp: true,
            algorithms: vec![crate::Algorithm::RS256],
            leeway: 0,
            sub: None,
            aud: None,
            iss: Some("https://example.com/test".to_owned()),
        };

        let _result: crate::TokenData<()> = key_set.verify(&valid_token(), &validation).unwrap();
    }

    #[test]
    #[should_panic(expected = "NoWorkingKey")]
    fn test_verify_invalid_signature() {
        let key = crate::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), N, E);

        let mut key_set = JWKDecodingKeySet::new();

        key_set.add_key(key.unwrap());

        let validation = crate::Validation {
            validate_nbf: true,
            validate_exp: true,
            algorithms: vec![crate::Algorithm::RS256],
            leeway: 0,
            sub: None,
            aud: None,
            iss: Some("https://example.com/test".to_owned()),
        };
        let valid_token = valid_token();
        let mut split = valid_token.rsplitn(2, '.');
        let _ = split.next();
        let token = split.next().unwrap().to_string() + INV_CERT;
        println!("{:?}", token);
        let _result: crate::TokenData<()> = key_set.verify(&token, &validation).unwrap();
    }
}