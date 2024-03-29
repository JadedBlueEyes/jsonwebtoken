use chrono::Utc;
use jsonwebtoken_rustcrypto::dangerous_insecure_decode_with_validation;
use jsonwebtoken_rustcrypto::{
    dangerous_insecure_decode, decode, decode_header, encode, headers::JwtHeader, Algorithm,
    DecodingKey, EncodingKey, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn mismatching_algorithms_key() {
    let claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let _ = encode(
        &JwtHeader::new(jsonwebtoken_rustcrypto::Algorithm::None),
        &claims,
        &EncodingKey::from_secret(b"aa"),
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn mismatching_algorithms_header() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let claims = encode(&JwtHeader::new(Algorithm::HS256), &my_claims, &EncodingKey::from_none());
    claims.unwrap();
}

#[test]
fn decode_token() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let claims = decode::<Claims>(token, &DecodingKey::from_none(), &Validation::no_expiry());
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
fn decode_token_invalid_signature() {
    let token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9.wrong";
    let claims = decode::<Claims>(token, &DecodingKey::from_none(), &Validation::no_expiry());
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn decode_token_invalid_signature_wrong_alg() {
    let token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjIzODh9.wrong";
    let claims =
        decode::<Claims>(token, &DecodingKey::from_secret(b"secret"), &Validation::no_expiry());
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::RS512),
    );
    claims.unwrap();
}

#[test]
fn decode_header_only() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let header = decode_header(token).unwrap();
    assert_eq!(header.general_headers.alg, Some(Algorithm::None));
    assert_eq!(header.general_headers.typ, Some("JWT".to_string()));
}

#[test]
fn dangerous_insecure_decode_token() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let claims = dangerous_insecure_decode::<Claims>(token);
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidToken")]
fn dangerous_insecure_decode_token_missing_parts() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let claims = dangerous_insecure_decode::<Claims>(token);
    claims.unwrap();
}

#[test]
fn dangerous_insecure_decode_token_with_validation() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let claims =
        dangerous_insecure_decode_with_validation::<Claims>(token, &Validation::no_expiry());
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
fn dangerous_insecure_decode_token_with_validation_no_signature() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let claims =
        dangerous_insecure_decode_with_validation::<Claims>(token, &Validation::no_expiry());
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
fn dangerous_insecure_decode_token_with_validation_extraneous_signature() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9.wrong";
    let claims =
        dangerous_insecure_decode_with_validation::<Claims>(token, &Validation::no_expiry());
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn dangerous_insecure_decode_token_with_validation_wrong_algorithm() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2ODE1MjI3MTF9";
    let claims = dangerous_insecure_decode_with_validation::<Claims>(
        token,
        &Validation::new(Algorithm::ES256),
    );
    println!("{:?}", claims);
    claims.unwrap();
}
