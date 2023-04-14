use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken_rustcrypto::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

fn bench_encode_hmac(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_encode", |b| {
        b.iter(|| {
            encode(
                black_box(&Header::new(jsonwebtoken_rustcrypto::Algorithm::HS256)),
                black_box(&claim),
                black_box(&key),
            )
        })
    });
}

fn bench_decode_verify_hmac(c: &mut Criterion) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    let key = DecodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_decode", |b| {
        b.iter(|| {
            decode::<Claims>(black_box(token), black_box(&key), black_box(&Validation::default()))
        })
    });
}

fn bench_encode_none(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_none();

    c.bench_function("bench_encode_none", |b| {
        b.iter(|| {
            encode(
                black_box(&Header::new(jsonwebtoken_rustcrypto::Algorithm::None)),
                black_box(&claim),
                black_box(&key),
            )
        })
    });
}

fn bench_decode_verify_none(c: &mut Criterion) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
    let key = DecodingKey::from_none();

    c.bench_function("bench_decode_verify_none", |b| {
        b.iter(|| {
            decode::<Claims>(black_box(token), black_box(&key), black_box(&Validation::default()))
        })
    });
}

criterion_group!(
    benches,
    bench_encode_hmac,
    bench_decode_verify_hmac,
    bench_encode_none,
    bench_decode_verify_none
);
criterion_main!(benches);
