#![doc = include_str!("../README.md")]
// #![deny(missing_docs)]

/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod serialization;
mod validation;
// JWK and JWKS types and functions
pub mod jwk;
pub(crate) mod registries;

#[allow(deprecated)]
pub use decoding::dangerous_unsafe_decode;
pub use decoding::{
    dangerous_insecure_decode, dangerous_insecure_decode_with_validation, decode, decode_header,
    DecodingKey, TokenData,
};
pub use encoding::{encode, EncodingKey};
pub use registries::{Algorithm, Header};
pub use validation::Validation;
