const RSA_ALGORITHMS: &[(jsonwebtoken_rustcrypto::Algorithm, jsonwebtoken::Algorithm)] = &[
    (jsonwebtoken_rustcrypto::Algorithm::RS256, jsonwebtoken::Algorithm::RS256),
    (jsonwebtoken_rustcrypto::Algorithm::RS384, jsonwebtoken::Algorithm::RS384),
    (jsonwebtoken_rustcrypto::Algorithm::RS512, jsonwebtoken::Algorithm::RS512),
    // (jsonwebtoken_rustcrypto::Algorithm::PS256, jsonwebtoken::Algorithm::PS256),
    // (jsonwebtoken_rustcrypto::Algorithm::PS384, jsonwebtoken::Algorithm::PS384),
    // (jsonwebtoken_rustcrypto::Algorithm::PS512, jsonwebtoken::Algorithm::PS512),
];

#[test]
fn round_trip_sign_verification_pem_pkcs1_jsonwebtoken_to_crate() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey: rsa::RsaPublicKey =
        rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(include_str!("public_rsa_key_pkcs1.pem"))
            .unwrap();

    for (alg_rc, alg_ring) in RSA_ALGORITHMS {
        let encrypted = jsonwebtoken::crypto::sign(
            "hello world".as_bytes(),
            &jsonwebtoken::EncodingKey::from_rsa_pem(privkey_pem).unwrap(),
            *alg_ring,
        )
        .unwrap();
        let is_valid = jsonwebtoken_rustcrypto::crypto::verify(
            &encrypted,
            "hello world",
            &jsonwebtoken_rustcrypto::DecodingKey::from_rsa(pubkey.clone()).unwrap(),
            *alg_rc,
        )
        .unwrap();
        assert!(is_valid, "{:?} signature was not valid.", alg_rc);
    }
}

#[test]
fn round_trip_sign_verification_pem_pkcs1_crate_to_jsonwebtoken() {
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");
    let privkey: rsa::RsaPrivateKey =
        rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_pem(include_str!("private_rsa_key_pkcs1.pem"))
            .unwrap();

    for (alg_rc, alg_ring) in RSA_ALGORITHMS {
        let encrypted = jsonwebtoken_rustcrypto::crypto::sign(
            "hello world",
            &jsonwebtoken_rustcrypto::EncodingKey::from_rsa(privkey.clone()).unwrap(),
            *alg_rc,
        )
        .unwrap();
        let is_valid = jsonwebtoken::crypto::verify(
            &encrypted,
            "hello world".as_bytes(),
            &jsonwebtoken::DecodingKey::from_rsa_pem(pubkey_pem).unwrap(),
            *alg_ring,
        )
        .unwrap();
        assert!(is_valid, "{:?} signature was not valid.", alg_rc);
    }
}
