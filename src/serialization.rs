use base64::Engine;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::map::Map;
use serde_json::{from_str, to_string, Value};

use crate::errors::Result;

pub(crate) fn b64_encode(input: &[u8]) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new().with_encode_padding(false),
    );
    engine.encode(input)
}

pub(crate) fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    Ok(engine.decode(input)?)
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = to_string(input)?;
    Ok(b64_encode(json.as_bytes()))
}

/// Decodes from base64 and deserializes from JSON to a struct AND a hashmap of Value so we can
/// run validation on it
pub(crate) fn from_jwt_part_claims<B: AsRef<str>, T: DeserializeOwned>(
    encoded: B,
) -> Result<(T, Map<String, Value>)> {
    let s = String::from_utf8(b64_decode(encoded.as_ref())?)?;

    let claims: T = from_str(&s)?;
    let validation_map: Map<_, _> = from_str(&s)?;
    Ok((claims, validation_map))
}
