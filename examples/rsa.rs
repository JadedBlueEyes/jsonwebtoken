use chrono::Utc;
use jsonwebtoken_rustcrypto::{
    decode, encode, headers::JwtHeader, Algorithm, DecodingKey, EncodingKey, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

const RSA_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let privkey: rsa::RsaPrivateKey = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_pem(
        include_str!("../tests/rsa/private_jwtio.pem"),
    )
    .unwrap();
    let pubkey: rsa::RsaPublicKey = rsa::pkcs8::DecodePublicKey::from_public_key_pem(include_str!(
        "../tests/rsa/public_jwtio.pem"
    ))
    .unwrap();

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };

    // let's try with every signature scheme!
    for &alg in RSA_ALGORITHMS {
        let token = encode(
            &JwtHeader::new(alg),
            &my_claims,
            &EncodingKey::from_rsa(privkey.clone()).unwrap(),
        )
        .unwrap();
        println!("{:?}: {}", alg, token);
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa(pubkey.clone()).unwrap(),
            &Validation::new(alg),
        )
        .unwrap();

        // Claims should be exactly the same when roundtripped
        assert_eq!(my_claims, token_data.claims);
    }
    Ok(())
}
