use chrono::Utc;
use jsonwebtoken::{
    crypto::{sign, verify},
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::{RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};

const RSA_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    // Algorithm::PS256,
    // Algorithm::PS384,
    // Algorithm::PS512,
];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    base64::decode(pem.split('\n').filter(|line| !line.starts_with('-')).fold(
        String::new(),
        |mut data, line| {
            data.push_str(&line);
            data
        },
    ))
    .unwrap()
}

#[test]
fn round_trip_sign_verification_pem_pkcs1() {
    let privkey =
        RSAPrivateKey::from_pkcs1(&pem_to_der(include_str!("private_rsa_key_pkcs1.pem"))).unwrap();
    let pubkey =
        RSAPublicKey::from_pkcs1(&pem_to_der(include_str!("public_rsa_key_pkcs1.pem"))).unwrap();

    for &alg in RSA_ALGORITHMS {
        let encrypted =
            sign("hello world", &EncodingKey::from_rsa(privkey.clone()).unwrap(), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa(pubkey.clone()).unwrap(), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_sign_verification_pem_pkcs8() {
    let privkey =
        RSAPrivateKey::from_pkcs8(&pem_to_der(include_str!("private_rsa_key_pkcs8.pem"))).unwrap();
    let pubkey =
        RSAPublicKey::from_pkcs8(&pem_to_der(include_str!("public_rsa_key_pkcs8.pem"))).unwrap();

    for &alg in RSA_ALGORITHMS {
        let encrypted =
            sign("hello world", &EncodingKey::from_rsa(privkey.clone()).unwrap(), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa(pubkey.clone()).unwrap(), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_sign_verification_der() {
    let privkey = RSAPrivateKey::from_pkcs1(include_bytes!("private_rsa_key.der")).unwrap();
    let pubkey = RSAPublicKey::from_pkcs1(include_bytes!("public_rsa_key.der")).unwrap();

    for &alg in RSA_ALGORITHMS {
        let encrypted =
            sign("hello world", &EncodingKey::from_rsa(privkey.clone()).unwrap(), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa(pubkey.clone()).unwrap(), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let privkey =
        RSAPrivateKey::from_pkcs1(&pem_to_der(include_str!("private_rsa_key_pkcs1.pem"))).unwrap();
    let pubkey =
        RSAPublicKey::from_pkcs1(&pem_to_der(include_str!("public_rsa_key_pkcs1.pem"))).unwrap();

    for &alg in RSA_ALGORITHMS {
        let token =
            encode(&Header::new(alg), &my_claims, &EncodingKey::from_rsa(privkey.clone()).unwrap())
                .unwrap();
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa(pubkey.clone()).unwrap(),
            &Validation::new(alg),
        )
        .unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[test]
fn roundtrip_with_jwtio_example_jey() {
    let privkey =
        RSAPrivateKey::from_pkcs1(&pem_to_der(include_str!("private_jwtio.pem"))).unwrap();
    let pubkey = RSAPublicKey::from_pkcs8(&pem_to_der(include_str!("public_jwtio.pem"))).unwrap();

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };

    for &alg in RSA_ALGORITHMS {
        let token =
            encode(&Header::new(alg), &my_claims, &EncodingKey::from_rsa(privkey.clone()).unwrap())
                .unwrap();
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa(pubkey.clone()).unwrap(),
            &Validation::new(alg),
        )
        .unwrap();
        assert_eq!(my_claims, token_data.claims);
    }
}
