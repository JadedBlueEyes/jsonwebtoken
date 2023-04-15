pub use crate::registries::{
    AesGcmHeaders, ClaimHeaders, ECDHKeyAgreementHeaders, GeneralHeaders, JwkSetHeaders,
    MiscProtectedHeaders, Pbes2Headers, X509Headers,
};
use crate::Algorithm;
use serde::{Deserialize, Serialize};

// note: it looks like serde_flatten has a ~25% performance penalty?
// Look into a way to skip all this work or make it faster.

/// A comprehensive JWT header.
/// By default, every field is empty.
/// WARNING: this struct is not exhaustive. Always construct with `..Default::default()`.
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct JwtHeader {
    #[serde(flatten)]
    pub general_headers: GeneralHeaders,
    #[serde(flatten)]
    pub jwk_set_headers: JwkSetHeaders,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub x509_headers: Option<Box<X509Headers>>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub claim_headers: Option<ClaimHeaders>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub ecdh_key_agreement_headers: Option<ECDHKeyAgreementHeaders>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub aes_gcm_headers: Option<AesGcmHeaders>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub pbes2_headers: Option<Pbes2Headers>,
    #[serde(flatten)]
    pub misc_protected_headers: MiscProtectedHeaders,
}

/// A comprehensive JWT header.
/// By default, every field is empty.
/// WARNING: this struct is not exhaustive. Always construct with `..Default::default()`.
impl JwtHeader {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Self {
        JwtHeader {
            general_headers: GeneralHeaders {
                typ: Some("JWT".to_string()),
                alg: Some(algorithm),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
