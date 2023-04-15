# jsonwebtoken-rustcrypto

- This is a [JWT] library for Rust that uses the [RustCrypto] family of crates.
- It provides support for [many of the commonly used signing algorithms](#supported-algorithms) and allows [validation of token claims upon decoding](#validation). 
<!-- - It is [significantly faster](#performance) than alternatives.  -->
- It also provides an implementation of [JSON Web Key Sets](#jwkS)

[jwt]: https://jwt.io
[rustcrypto]: https://github.com/RustCrypto

## Installation

Add the following to Cargo.toml:

```toml
jsonwebtoken-rustcrypto = "1"
serde = {version = "1", features = ["derive"] }
```

## How to use

<!-- see examples/simple.rs -->

```rust
use chrono::Utc;
use jsonwebtoken_rustcrypto::{decode, encode, DecodingKey, EncodingKey, headers::JwtHeader, Validation, Algorithm};
use serde::{Deserialize, Serialize};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

let my_claims = Claims {
    sub: "b@b.com".to_string(),
    company: "ACME".to_string(),
    exp: Utc::now().timestamp() as usize + 10000,
};

let token =
    encode(&JwtHeader::new(Algorithm::HS512), &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;

println!("Our encoded token: {token}");

let token_data = decode::<Claims>(
    &token,
    &DecodingKey::from_secret("secret".as_ref()),
    &Validation::default(),
)?;

assert_eq!(my_claims, token_data.claims);

println!("Our decoded token: {:?}", token_data);

# Ok::<(), Box<dyn std::error::Error>>(())
```

### Encoding

```rust ignore
// HS256
let token = encode(&JwtHeader::new(Algorithm::HS256), &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;
// RSA
let token = encode(&JwtHeader::new(Algorithm::RS256), &my_claims, &EncodingKey::from_rsa(RSAPrivateKey::new(&mut rng, bits).unwrap())?)?;
```

Encoding a JWT takes 3 parameters:

-   A header: the `JwtHeader` struct
-   Some claims: your own struct
-   A key/secret

When using HS256, HS2384 or HS512, the key is always a shared secret - like in the first example. When using RSA, the key should always be the content of the private key in the PEM or DER format.

If your key is in PEM format, it is better performance wise to generate the `EncodingKey` once in a `lazy_static` or
something similar and reuse it.

### Decoding

```rust ignore
// `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
let token = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::default())?;
```

Decoding a JWT also takes 3 parameters:

-   The token to decode
-   A key to validate the signature against
-   A validation scheme (the `Validation` struct)

Additionally, it takes the struct type the claims should deserialise into as a type parameter.

It returns a `TokenData<T>` struct, where `T` is the claims struct.

`decode` can error for a variety of reasons:

-   the token or its signature is invalid
-   the token had invalid base64
-   validation of at least one reserved claim failed

As with encoding, when using HS256, HS2384 or HS512, the key is always a shared secret like in the first example. When using RSA, the key should always be the content of the public key in the PEM or DER format.

In some cases, for example if you need to grab the `kid`, you can choose to decode only the header:

```rust ignore
let header = decode_header(&token)?;
```

This does not perform any signature verification or validate the token claims. It's mainly there to support JWKS implementations.

### Custom headers & changing algorithm

All the parameters from the RFC are supported but the default header only has `typ` and `alg` set.
If you want to set the `kid` parameter or change the algorithm for example:

```rust ignore
let mut header = JwtHeader::new(Algorithm::HS384);
header.kid = Some("blabla".to_owned());
let token = encode(&header, &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;
```

Look at `examples/custom_header.rs` for a full working example.

### Validation

The library is aware of, and can validate, many of the fields you will find in a JWT. What and how it validates these can be configured with the `Validation` struct.

#### Claims

The claims fields which can be validated.

```rust
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,         // Audience
    exp: usize,          // Expiration time (as UTC timestamp)
    iat: usize,          // Issued at (as UTC timestamp)
    iss: String,         // Issuer
    nbf: usize,          // Not Valid Before (as UTC timestamp)
    sub: String,         // Subject (whom token refers to)
}
```

By default, `exp` is required and validated, and all the others are not.

#### JwtHeader validation

Additionally, the header `alg` field is validated. By default, any algorithm compatible with your keys is valid. However, this can be configured to only accept specified algorithms.

#### Example validation configurations

```rust
use jsonwebtoken_rustcrypto::{Validation, Algorithm};

// Default validation: only expiration is checked.
let validation = Validation::default();

// Quick way to setup a validation where only one algorithm is allowed.
let validation = Validation::new(Algorithm::HS512);

// Adding some leeway (in seconds) for time-based checks (like expiry and not-before)
let mut validation = Validation {leeway: 60, ..Default::default()};

// Check the issuer is equal to a specific string
let mut validation = Validation {iss: Some("issuer".to_string()), ..Default::default()};

// Check the audience is one of the given values.
let mut validation = Validation::default();
validation.set_audience(&"Me"); // string
validation.set_audiences(&["Me", "You"]); // array of strings
```

Look at `examples/validation.rs` for a full working example.

### JWKS

There is a JWK implementation under the `jwk` module.

## Supported algorithms

This library currently supports the following signing algorithms:

- none
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- PS256
- PS384
- PS512

### Unsupported algorithms

-   ES256
-   ES256K
-   ES384
-   ES512
-   EdDSA

## More about this crate.

This is a fork of the [Keats/jsonwebtoken](https://github.com/Keats/jsonwebtoken) crate that uses RustCrypto crates (`rsa`, `sha2`, `hmac`) instead of Ring.
This reduces the amount of code in the crate significantly and allows more flexibility in how the user loads RSA keys.

Caveats compared to the original:

-   No ECDSA: I didn't have a need for ECDSA or the time to research and implement EC using RustCrypto crates and I removed it to completely remove the ring dependency.
-   HMAC signature verification doesn't use constant time comparison like Keats's original does.

<!-- 
### Performance

This crate is roughly ~30-40% faster than `jsonwebtoken`, although that is mostly incidental - performance is not the primary goal of this fork.


```text
     Running benches/jwt.rs (~/.cache/cargo-target/release/deps/jwt-35f765b950aab3a3)
bench_encode            time:   [734.68 ns 736.72 ns 738.93 ns]                          
                        change: [-42.608% -42.334% -42.079%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) high mild
  5 (5.00%) high severe

bench_decode            time:   [1.3172 µs 1.3287 µs 1.3430 µs]                          
                        change: [-33.374% -32.445% -31.518%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe
``` -->
