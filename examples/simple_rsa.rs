use chrono::Utc;
use jsonwebtoken_rustcrypto::{
    decode, encode, headers::JwtHeader, Algorithm, DecodingKey, EncodingKey, Validation,
};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Grab public and/or private keys from any source supported by the `rsa` crate.
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::from_pkcs1_pem(include_str!("../tests/rsa/private_jwtio.pem"))?;
    let pub_key: RsaPublicKey =
        RsaPublicKey::from_public_key_pem(include_str!("../tests/rsa/public_jwtio.pem"))?;

    // Create the keys
    let enc_key = EncodingKey::from_rsa(priv_key)?;
    let dec_key = DecodingKey::from_rsa(pub_key)?;

    let header = JwtHeader::new(Algorithm::RS256);

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() as usize + 10000,
    };

    let token = encode(&header, &my_claims, &enc_key)?;

    println!("Our encoded token: {token}");

    let token_data = decode::<Claims>(&token, &dec_key, &Validation::new(Algorithm::RS256))?;

    assert_eq!(my_claims, token_data.claims);

    println!("Our decoded token: {:?}", token_data);

    Ok(())
}
