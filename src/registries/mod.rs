use serde::{self, Deserialize, Serialize};

// See https://www.iana.org/assignments/jose/jose.xhtml
use crate::errors::{Error, ErrorKind, Result};
use crate::serialization::b64_decode;
use std::str::FromStr;
macro_rules! make_values_enum {
    (   $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$item_meta:meta])* $item_name:ident, $value:literal, $docstring:literal, $($spec:literal)?)*
        }
    ) => {

        $(#[$meta])*
        #[non_exhaustive]
        $vis enum $name {
            $(
                // $(#[depreciated = $depreciated])?
                #[serde(rename = $value)]
                #[doc = $docstring]
                $(#[doc ="\n"] #[doc ="Spec: "] #[doc = $spec])?
                $(#[$item_meta])*
                $item_name
            ),*
        }
    }
}

// https://www.iana.org/assignments/jose/jose.xhtml#web-key-use
make_values_enum! {
    /// The intended use of the key.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Hash)]
    pub enum WebKeyUse {
        Signature, "sig","Digital Signature or MAC ", "RFC7517, Section 4.2"
        Encryption, "enc","Encryption ", "RFC7517, Section 4.2"
    }
}

// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// web-signature-encryption-algorithms.csv
make_values_enum! {
    /// The possible algorithms for signing JWTs.
    #[derive(Debug, PartialEq, Hash, Copy, Clone, Serialize, Deserialize, Default)]
    pub enum Algorithm {
#[default] None,"none","No digital signature or MAC performed", "RFC7518, Section 3.6"
HS256,"HS256","HMAC using SHA-256", "RFC7518, Section 3.2"
HS384,"HS384","HMAC using SHA-384", "RFC7518, Section 3.2"
HS512,"HS512","HMAC using SHA-512", "RFC7518, Section 3.2"
RS256,"RS256","RSASSA-PKCS1-v1_5 using SHA-256", "RFC7518, Section 3.3"
RS384,"RS384","RSASSA-PKCS1-v1_5 using SHA-384", "RFC7518, Section 3.3"
RS512,"RS512","RSASSA-PKCS1-v1_5 using SHA-512", "RFC7518, Section 3.3"
PS256,"PS256","RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "RFC7518, Section 3.5"
PS384,"PS384","RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "RFC7518, Section 3.5"
PS512,"PS512","RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "RFC7518, Section 3.5"
Rsa15,"RSA1_5","RSAES-PKCS1-v1_5", "RFC7518, Section 4.2"
RsaOeap,"RSA-OAEP","RSAES OAEP using default parameters", "RFC7518, Section 4.3"
RsaOeap256,"RSA-OAEP-256","RSAES OAEP using SHA-256 and MGF1 with SHA-256", "RFC7518, Section 4.3"
ES256,"ES256","ECDSA using P-256 and SHA-256", "RFC7518, Section 3.4"
ES256K,"ES256K","ECDSA using secp256k1 curve and SHA-256", "RFC8812, Section 3.2"
ES384,"ES384","ECDSA using P-384 and SHA-384", "RFC7518, Section 3.4"
ES512,"ES512","ECDSA using P-521 and SHA-512", "RFC7518, Section 3.4"
EdDSA,"EdDSA","EdDSA signature algorithms", "RFC8037, Section 3.1"
EcdhEs,"ECDH-ES","ECDH-ES using Concat KDF", "RFC7518, Section 4.6"
EcdhEsA128Kw,"ECDH-ES+A128KW","ECDH-ES using Concat KDF and \"A128KW\" wrapping", "RFC7518, Section 4.6"
EcdhEsA192Kw,"ECDH-ES+A192KW","ECDH-ES using Concat KDF and \"A192KW\" wrapping", "RFC7518, Section 4.6"
EcdhEsA256Kw,"ECDH-ES+A256KW","ECDH-ES using Concat KDF and \"A256KW\" wrapping", "RFC7518, Section 4.6"
A128Kw,"A128KW","AES Key Wrap using 128-bit key", "RFC7518, Section 4.4"
A192Kw,"A192KW","AES Key Wrap using 192-bit key", "RFC7518, Section 4.4"
A256Kw,"A256KW","AES Key Wrap using 256-bit key", "RFC7518, Section 4.4"
A128GcmKw,"A128GCMKW","Key wrapping with AES GCM using 128-bit key", "RFC7518, Section 4.7"
A192GcmKw,"A192GCMKW","Key wrapping with AES GCM using 192-bit key", "RFC7518, Section 4.7"
A256GcmKw,"A256GCMKW","Key wrapping with AES GCM using 256-bit key", "RFC7518, Section 4.7"
Pbes2HS256A128Kw,"PBES2-HS256+A128KW","PBES2 with HMAC SHA-256 and \"A128KW\" wrapping", "RFC7518, Section 4.8"
Pbes2HS384A192Kw,"PBES2-HS384+A192KW","PBES2 with HMAC SHA-384 and \"A192KW\" wrapping", "RFC7518, Section 4.8"
Pbes2HS512A256Kw,"PBES2-HS512+A256KW","PBES2 with HMAC SHA-512 and \"A256KW\" wrapping", "RFC7518, Section 4.8"
Direct,"dir","Direct use of a shared symmetric key", "RFC7518, Section 4.5"
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        serde_plain::from_str::<Algorithm>(s).or(Err(ErrorKind::InvalidAlgorithmName.into()))
    }
}

make_values_enum! {
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Hash)]
/// The eliptic curve used in this JWK, if the key type is "EC"
    pub enum ElipticCurve {
P256,"P-256","P-256 Curve","RFC7518, Section 6.2.1.1"
P384,"P-384","P-384 Curve","RFC7518, Section 6.2.1.1"
P521,"P-521","P-521 Curve","RFC7518, Section 6.2.1.1"
Ed25519,"Ed25519","Ed25519 signature algorithm key pairs","RFC8037, Section 3.1"
Ed448,"Ed448","Ed448 signature algorithm key pairs","RFC8037, Section 3.1"
X25519,"X25519","X25519 function key pairs","RFC8037, Section 3.1"
X448,"X448","X448 function key pairs","RFC8037, Section 3.1"
Secp256k1,"secp256k1","SECG secp256k1 curve","RFC8812, Section 3.1"
    }
}

make_values_enum! {
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Hash)]
/// The type of key in this JWK.
    pub enum KeyOps {
Sign,"sign","Compute digital signature or MAC","RFC7517, Section 4.3"
Verify,"verify","Verify digital signature or MAC","RFC7517, Section 4.3"
Encrypt,"encrypt","Encrypt content","RFC7517, Section 4.3"
Decrypt,"decrypt","Decrypt content and validate decryption, if applicable","RFC7517, Section 4.3"
WrapKey,"wrapKey","Encrypt key","RFC7517, Section 4.3"
UnwrapKey,"unwrapKey","Decrypt key and validate decryption, if applicable","RFC7517, Section 4.3"
DeriveKey,"deriveKey","Derive key","RFC7517, Section 4.3"
DeriveBits,"deriveBits","Derive bits not to be used as a key","RFC7517, Section 4.3"
    }
}

macro_rules! make_struct {
    (   $(#[$meta:meta])*
        $vis:vis struct $name:ident {$(
            $(#[$item_meta:meta])* $item_name:ident,
            $value:literal,
            $docstring_head:literal,
            $type:ident$(<$lt:tt$(<$lt2:tt>)?>)?,
            $($docstring_body:literal)?,
            $($spec:literal)?
        )*}
    ) => {

        $(#[$meta])*
        #[non_exhaustive]
        $vis struct $name {
            $(
                #[serde(rename = $value)]
                #[doc = $docstring_head]
                $(#[doc = "\n"] #[doc = $docstring_body])?
                $(#[doc ="\n"] #[doc ="Spec: "] #[doc = $spec])?
                $(#[$item_meta])*
                pub $item_name: $type$(<$lt$(<$lt2>)?>)?
            ),*
        }
    }
}

make_struct! {
    #[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
    pub struct JwkSet {
keys,"keys","# Array of JWK Values",Vec<Jwk>,,"RFC7517, Section 5.1"
    }
}

make_struct! {
    /// see [`Jwk`] `oth` property
    #[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
    pub struct OtherPrimeInfo {
r,"r","# Prime Factor",Option<String>,,"RFC7518, Section 6.3.2.7.1"
d,"d","# Factor CRT Exponent",Option<String>,,"RFC7518, Section 6.3.2.7.2"
t,"t","# Factor CRT Coefficient",Option<String>,,"RFC7518, Section 6.3.2.7.3"
    }
}

macro_rules! make_keys_enum {
    (   $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant_name:ident, $variant_value:literal, $docstring:literal, $($variant_spec:literal)? {$(
            $(#[$item_meta:meta])* $item_name:ident,
            $item_value:literal,
            $docstring_head:literal,
            $type:ident$(<$lt:tt$(<$lt2:tt$(<$lt3:tt>)?>)?>)?,
            $($docstring_body:literal)?,
            $($item_spec:literal)?
        )*
            })*
        }
    ) => {

        $(#[$meta])*
        #[non_exhaustive]
        $vis enum $name {
            $(
                // $(#[depreciated = $depreciated])?
                #[serde(rename = $variant_value)]
                #[doc = $docstring]
                $(#[doc ="\n"] #[doc ="Spec: "] #[doc = $variant_spec])?
                $(#[$variant_meta])*
                #[non_exhaustive]
                $variant_name

        {
            $(
                #[serde(rename = $item_value)]
                #[doc = $docstring_head]
                #[doc = "\n"]
                $(#[doc = $docstring_body])?
                $(#[doc ="\n"] #[doc ="Spec: "] #[doc = $item_spec])?
                $(#[$item_meta])*
                $item_name: $type$(<$lt$(<$lt2$(<$lt3>)?>)?>)?
            ),*
        }
            ),*
        }
    }
}

make_keys_enum! {
/// The type of key in this JWK.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Hash)]
#[serde(tag = "kty")]
    pub enum JsonWebKeyType {
Rsa,"RSA","RSA","RFC7518, Section 6.3" {
    n,"n","Modulus",Option<String>,,"RFC7518, Section 6.3.1.1"
    e,"e","Exponent",Option<String>,,"RFC7518, Section 6.3.1.2"
    d,"d","Private Exponent",Option<String>,,"RFC7518, Section 6.3.2.1"
    p,"p","First Prime Factor",Option<String>,,"RFC7518, Section 6.3.2.2"
    q,"q","Second Prime Factor",Option<String>,,"RFC7518, Section 6.3.2.3"
    dp,"dp","First Factor CRT Exponent",Option<String>,,"RFC7518, Section 6.3.2.4"
    dq,"dq","Second Factor CRT Exponent",Option<String>,,"RFC7518, Section 6.3.2.5"
    qi,"qi","First CRT Coefficient",Option<String>,,"RFC7518, Section 6.3.2.6"
    oth,"oth","Other Primes Info",Option<Vec<OtherPrimeInfo> >,"Contains any third and subsequent primes.","RFC7518, Section 6.3.2.7"
}
OctetSeq,"oct","Octet sequence","RFC7518, Section 6.4" {
    k,"k","Key Value",Option<String>,,"RFC7518, Section 6.4.1"
}
Ec,"EC","Elliptic Curve","RFC7518, Section 6.2" {
    crv,"crv","Curve",Option<ElipticCurve>,,"RFC7518, Section 6.2.1.1"
    x,"x","X Coordinate",Option<String>,,"RFC7518, Section 6.2.1.2"
    y,"y","Y Coordinate",Option<String>,,"RFC7518, Section 6.2.1.3"
    d,"d","ECC Private Key",Option<String>,,"RFC7518, Section 6.2.2.1"

}
OctetStringPairs,"OKP","Octet string key pairs","RFC8037, Section 2" {
    crv,"crv","The subtype of key pair",Option<ElipticCurve>,,"RFC8037, Section 2"
    d,"d","The private key",Option<String>,,"RFC8037, Section 2"
    x,"x","The public key",Option<String>,,"RFC8037, Section 2"
}
    }
}

make_struct! {
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Hash)]
    pub struct Jwk {
#[serde(flatten)] kty,"kty","Key Type",JsonWebKeyType,,"RFC7517, Section 4.1"
key_use,"use","Public Key Use",Option<WebKeyUse>,,"RFC7517, Section 4.2"
key_ops,"key_ops","Key Operations",Option<KeyOps>,,"RFC7517, Section 4.3"
alg,"alg","Algorithm",Option<Algorithm>,,"RFC7517, Section 4.4"
kid,"kid","Key ID",Option<String>,,"RFC7517, Section 4.5"
x5u,"x5u","X.509 URL",Option<String>,,"RFC7517, Section 4.6"
x5c,"x5c","X.509 Certificate Chain",Option<Vec<String> >,,"RFC7517, Section 4.7"
x5t,"x5t","X.509 Certificate SHA-1 Thumbprint",Option<String>,,"RFC7517, Section 4.8"
x5t_s256,"x5t#S256","X.509 Certificate SHA-256 Thumbprint",Option<String>,,"RFC7517, Section 4.9"
ext,"ext","Extractable",Option<bool>,,"<https://www.w3.org/TR/WebCryptoAPI>"
    }
}

macro_rules! make_header {
    (   $(#[$meta:meta])*
        $vis:vis struct $name:ident {$(
            $(#[$item_meta:meta])* $item_name:ident,
            $value:literal,
            $docstring_head:literal,
            $type:ident$(<$lt:tt>)?,
            $($docstring_body:literal)?, $($formats:literal)?,
            $($jwe_spec:literal)?, $($jws_spec:literal)?
        )*}
    ) => {

        $(#[$meta])*
        $vis struct $name {
            $(
                #[serde(rename = $value, skip_serializing_if = "Option::is_none")]
                #[doc = $docstring_head]
                #[doc = "\n"]
                $(#[doc = $docstring_body])?
                $(#[doc ="## Formats\n"] #[doc = $formats])?
                #[doc ="## Specification\n"]
                $(#[doc = $jwe_spec] #[doc ="\n"] )?
                $(#[doc = $jws_spec] #[doc ="\n"] )?
                $(#[$item_meta])*
                pub $item_name: Option<$type$(<$lt>)?>
            ),*
        }
    }
}

// see web-signature-encryption-header-paramaters.csv
make_header! {
    /// A comprehensive JOSE header.
    /// Defaults to JWT type and no algorithm.
    /// WARNING: this struct is not exhaustive. Always construct with `..Default::default()`.
    #[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
    pub struct Header {
typ,"typ","# Type",String,"The type of content encoded in the complete object (for example, JWT).","JWE, JWS","RFC7516, Section 4.1.11","RFC7515, Section 4.1.9"
alg,"alg","# Algorithm",Algorithm,"The specific [`Algorithm`] used to encrypt or sign the object.","JWE, JWS","RFC7516, Section 4.1.1","RFC7515, Section 4.1.1"
cty,"cty","# Content Type",String,"The type of the secured content / payload.","JWE, JWS","RFC7516, Section 4.1.12","RFC7515, Section 4.1.10"
b64,"b64","# Base64url-Encode Payload",bool,"Whether the payload is base64 encoded. If not present, defaults to true.","JWS",,"RFC7797, Section 3"
crit,"crit","# Critical",Vec<String>,"Any extensions to the header that MUST be understood.","JWE, JWS","RFC7516, Section 4.1.13","RFC7515, Section 4.1.11"
url,"url","# URL",String,"The URL to which the object is directed.","JWE, JWS","RFC8555, Section 6.4.1","RFC8555, Section 6.4.1"
nonce,"nonce","# Nonce",String,"A unique octet string that enables the verifier of a JWS to recognize when replay has occurred.","JWE, JWS","RFC8555, Section 6.5.2","RFC8555, Section 6.5.2"
jku,"jku","# JWK Set URL",String,"A URI that refers to a JWK Set containing the public key used to sign the object.","JWE, JWS","RFC7516, Section 4.1.4","RFC7515, Section 4.1.2"
jwk,"jwk","# JSON Web Key",Jwk,"The public key used to sign the object, represented as a JWK.","JWE, JWS","RFC7516, Section 4.1.5","RFC7515, Section 4.1.3"
kid,"kid","# Key ID",String,"A hint indicating which key was used to secure the JWS.","JWE, JWS","RFC7516, Section 4.1.6","RFC7515, Section 4.1.4"
iss,"iss","# Issuer",String,"The principal that issued the object.","JWE","RFC7519, Section 4.1.1",
sub,"sub","# Subject",String,"The principal that is the subject of the object.","JWE","RFC7519, Section 4.1.2",
aud,"aud","# Audience",Vec<String>,"The recipients that the object is intended for.","JWE","RFC7519, Section 4.1.3",
x5u,"x5u","# X.509 URL",String,,"JWE, JWS","RFC7516, Section 4.1.7","RFC7515, Section 4.1.5"
x5c,"x5c","# X.509 Certificate Chain",Vec<String>,,"JWE, JWS","RFC7516, Section 4.1.8","RFC7515, Section 4.1.6"
x5t,"x5t","# X.509 Certificate SHA-1 Thumbprint",String,,"JWE, JWS","RFC7516, Section 4.1.9","RFC7515, Section 4.1.7"
x5t_s256,"# x5t#S256","X.509 Certificate SHA-256 Thumbprint",String,,"JWE, JWS","RFC7516, Section 4.1.10","RFC7515, Section 4.1.8"
epk,"epk","# Ephemeral Public Key",Jwk,,"JWE","RFC7518, Section 4.6.1.1",
apu,"apu","# Agreement PartyUInfo",String,,"JWE","RFC7518, Section 4.6.1.2",
apv,"apv","# Agreement PartyVInfo",String,,"JWE","RFC7518, Section 4.6.1.3",
iv,"iv","# Initialization Vector",String,,"JWE","RFC7518, Section 4.7.1.1",
tag,"tag","# Authentication Tag",String,,"JWE","RFC7518, Section 4.7.1.2",
p2s,"p2s","# PBES2 Salt Input",String,,"JWE","RFC7518, Section 4.8.1.1",
p2c,"p2c","# PBES2 Count",u64,,"JWE","RFC7518, Section 4.8.1.2",
ppt,"ppt","# PASSporT extension identifier",Vec<String>,"Required extensions to parse the object.","JWS",,"RFC8225, Section 8.1"
svt,"svt","# Signature Validation Token",Vec<String>,"An array of JWTs in string format.\n<https://www.rfc-editor.org/rfc/rfc9321.html#name-svt-header-parameter>","JWS",,"RFC9321"
    }
}
/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.

impl Header {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Self {
        Header {
            typ: Some("JWT".to_string()),
            alg: Some(algorithm),
            cty: None,
            b64: None,
            crit: None,
            url: None,
            nonce: None,
            jku: None,
            jwk: None,
            kid: None,
            iss: None,
            sub: None,
            aud: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            epk: None,
            apu: None,
            apv: None,
            iv: None,
            tag: None,
            p2s: None,
            p2c: None,
            ppt: None,
            svt: None,
        }
    }

    /// Converts an encoded part into the Header struct if possible
    pub(crate) fn from_encoded(encoded_part: &str) -> Result<Self> {
        let decoded = b64_decode(encoded_part)?;
        let s = String::from_utf8(decoded)?;

        Ok(serde_json::from_str(&s)?)
    }
}

impl Default for Header {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        Header::new(Algorithm::default())
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::Algorithm;

    use super::*;

    #[test]
    fn generate_algorithm_enum_from_str() {
        assert!(Algorithm::from_str("HS256").is_ok());
        assert!(Algorithm::from_str("HS384").is_ok());
        assert!(Algorithm::from_str("HS512").is_ok());
        assert!(Algorithm::from_str("RS256").is_ok());
        assert!(Algorithm::from_str("RS384").is_ok());
        assert!(Algorithm::from_str("RS512").is_ok());
        assert!(Algorithm::from_str("PS256").is_ok());
        assert!(Algorithm::from_str("PS384").is_ok());
        assert!(Algorithm::from_str("PS512").is_ok());
        assert!(Algorithm::from_str("").is_err());
    }
}
