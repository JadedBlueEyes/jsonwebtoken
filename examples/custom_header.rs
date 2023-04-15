use serde::{Deserialize, Serialize};

use jsonwebtoken_rustcrypto::errors::ErrorKind;
use jsonwebtoken_rustcrypto::{
    decode, encode,
    headers::{JwkSetHeaders, JwtHeader},
    Algorithm, DecodingKey, EncodingKey, Validation,
};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = b"secret";

    let header = JwtHeader {
        jwk_set_headers: JwkSetHeaders {
            kid: Some("signing_key".to_owned()),
            ..Default::default()
        },
        ..JwtHeader::new(Algorithm::HS512)
    };

    let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);

    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!(),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}
