
use std::time::{SystemTime, UNIX_EPOCH};

use rsa::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};

use jsonwebtoken_rustcrypto::{
    jwk::{JWKDecodingKeySet, JWKS},
    Algorithm,
};

const PRIVATE_KEY: &str = include_str!("private.pem");



#[derive(Serialize, Deserialize)]
struct RsaComponents {
    E: String,
    N: String,
}

fn valid_token() -> String {
    let mut claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(TEST_CLAIMS).unwrap();
    claims["exp"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10).into();

    encode_token(claims)
}

fn early_token() -> String {
    let mut claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(TEST_CLAIMS).unwrap();
    claims["nbf"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 100).into();
    claims["exp"] = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 200).into();

    encode_token(claims)
}

fn expired_token() -> String {
    let claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(TEST_CLAIMS).unwrap();

    encode_token(claims)
}

fn encode_token(claims: serde_json::Map<String, serde_json::Value>) -> String {
    let key =
        jsonwebtoken_rustcrypto::EncodingKey::from_rsa(rsa::RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).unwrap())
            .unwrap();
    let mut header = jsonwebtoken_rustcrypto::Header::new(jsonwebtoken_rustcrypto::Algorithm::RS256);
    header.kid = Some("1".to_owned());
    jsonwebtoken_rustcrypto::encode(&header, &claims, &key).unwrap()
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

pub const INVALID_CERT: &str = ".XXXeTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

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
fn test_add_key() {

    let exponents: RsaComponents = serde_json::from_str(include_str!("rsa-components.json")).unwrap();

    let key = jsonwebtoken_rustcrypto::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), &exponents.N, &exponents.E);

    let mut key_set = JWKDecodingKeySet::new();

    assert_eq!(0usize, key_set.keys_len());

    key_set.add_key(key.unwrap());

    assert_eq!(1usize, key_set.keys_len());

    let result = key_set.keys_by_id("1".into());

    assert!(!result.is_empty());
}

#[test]
fn test_verify() {
    let exponents: RsaComponents = serde_json::from_str(include_str!("rsa-components.json")).unwrap();
    let key = jsonwebtoken_rustcrypto::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), &exponents.N, &exponents.E);

    let mut key_set = JWKDecodingKeySet::new();

    key_set.add_key(key.unwrap());

    let validation = jsonwebtoken_rustcrypto::Validation {
        validate_nbf: true,
        validate_exp: true,
        algorithms: vec![jsonwebtoken_rustcrypto::Algorithm::RS256],
        leeway: 15,
        sub: None,
        aud: None,
        iss: Some("https://example.com/test".to_owned()),
    };

    let result: Result<jsonwebtoken_rustcrypto::TokenData<TestClaims>, _> =
        key_set.verify(&valid_token(), &validation);

    assert!(result.is_ok(), "{:?}", result);

    let jwt = result.unwrap();

    assert_eq!("https://example.com/test", jwt.claims.iss);
    assert_eq!("Ada Lovelace", jwt.claims.name);
    assert_eq!("alovelace@example.com", jwt.claims.email);

    let result: Result<jsonwebtoken_rustcrypto::TokenData<TestClaims>, _> =
        key_set.verify(&early_token(), &validation); // early

    assert_eq!(format!("{:?}", result), r#"Err(Error(ImmatureSignature))"#);

    let result: Result<jsonwebtoken_rustcrypto::TokenData<TestClaims>, _> =
        key_set.verify(&expired_token(), &validation); // late

    assert_eq!(format!("{:?}", result), r#"Err(Error(ExpiredSignature))"#);
}

#[test]
#[should_panic(expected = "NoWorkingKey")]
fn test_verify_invalid_certificate() {
    let exponents: RsaComponents = serde_json::from_str(include_str!("rsa-components.json")).unwrap();
    let key = jsonwebtoken_rustcrypto::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), &exponents.N, &exponents.E);

    let mut key_set = JWKDecodingKeySet::new();

    key_set.add_key(key.unwrap());

    let validation = jsonwebtoken_rustcrypto::Validation {
        validate_nbf: true,
        validate_exp: true,
        algorithms: vec![jsonwebtoken_rustcrypto::Algorithm::RS256],
        leeway: 0,
        sub: None,
        aud: None,
        iss: Some("https://example.com/test".to_owned()),
    };

    let _result: jsonwebtoken_rustcrypto::TokenData<()> = key_set.verify(&valid_token(), &validation).unwrap();
}

#[test]
#[should_panic(expected = "NoWorkingKey")]
fn test_verify_invalid_signature() {
    let exponents: RsaComponents = serde_json::from_str(include_str!("rsa-components.json")).unwrap();
    let key = jsonwebtoken_rustcrypto::jwk::JWKDecodingKey::new_rsa(Some("1".into()), Some(Algorithm::RS256), &exponents.N, &exponents.E);

    let mut key_set = JWKDecodingKeySet::new();

    key_set.add_key(key.unwrap());

    let validation = jsonwebtoken_rustcrypto::Validation {
        validate_nbf: true,
        validate_exp: true,
        algorithms: vec![jsonwebtoken_rustcrypto::Algorithm::RS256],
        leeway: 0,
        sub: None,
        aud: None,
        iss: Some("https://example.com/test".to_owned()),
    };
    let valid_token = valid_token();
    let mut split = valid_token.rsplitn(2, '.');
    let _ = split.next();
    let token = split.next().unwrap().to_string() + INVALID_CERT;
    println!("{:?}", token);
    let _result: jsonwebtoken_rustcrypto::TokenData<()> = key_set.verify(&token, &validation).unwrap();
}
