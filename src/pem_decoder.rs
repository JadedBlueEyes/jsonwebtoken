use crate::errors::{ErrorKind, Result};
use crate::keys::Key;

extern crate pem;
extern crate simple_asn1;

use simple_asn1::{BigUint, OID};

/// Supported PEM files for EC and RSA Public and Private Keys
#[derive(Debug, PartialEq)]
enum PemType {
    EcPublicKey,
    EcPrivateKey,
    RsaPublicKey,
    RsaPrivateKey,
}

#[derive(Debug, PartialEq)]
enum Standard {
    Pkcs1,
    Pkcs8,
}

#[derive(Debug, PartialEq)]
enum Classification {
    Ec,
    Rsa,
}

/// The return type of a successful PEM encoded key with `decode_pem`
///
/// This struct gives a way to parse a string to a key for use in jsonwebtoken.
/// A struct is necessary as it provides the lifetime of the key
///
/// PEM public private keys are encoded PKCS#1 or PKCS#8
/// You will find that with PKCS#8 RSA keys that the PKCS#1 content
/// is embedded inside. This is what is provided to ring via `Key::Der`
/// For EC keys, they are always PKCS#8 on the outside but like RSA keys
/// EC keys contain a section within that ultimately has the configuration
/// that ring uses.
/// Documentation about these formats is at
/// PKCS#1: https://tools.ietf.org/html/rfc8017
/// PKCS#8: https://tools.ietf.org/html/rfc5958
#[derive(Debug)]
pub struct PemEncodedKey {
    content: Vec<u8>,
    asn1: Vec<simple_asn1::ASN1Block>,
    pem_type: PemType,
    standard: Standard,
}

impl PemEncodedKey {
    /// Read the PEM file for later key use
    pub fn read(input: &str) -> Result<PemEncodedKey> {
        match pem::parse(input) {
            Ok(content) => {
                let pem_contents = content.contents;
                let asn1_content = match simple_asn1::from_der(pem_contents.as_slice()) {
                    Ok(asn1) => asn1,
                    Err(_) => return Err(ErrorKind::InvalidKeyFormat.into()),
                };

                match content.tag.as_ref() {
                    // This handles a PKCS#1 RSA Private key
                    "RSA PRIVATE KEY" => Ok(PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPrivateKey,
                        standard: Standard::Pkcs1,
                    }),
                    "RSA PUBLIC KEY" => Ok(PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPublicKey,
                        standard: Standard::Pkcs1,
                    }),

                    // No "EC PRIVATE KEY"
                    // https://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
                    // "there is no such thing as a "PKCS#1 format" for elliptic curve (EC) keys"

                    // This handles PKCS#8 public & private keys
                    tag @ "PRIVATE KEY" | tag @ "PUBLIC KEY" => match classify_pem(&asn1_content) {
                        Some(c) => {
                            let is_private = tag == "PRIVATE KEY";
                            let pem_type = match c {
                                Classification::Ec => {
                                    if is_private {
                                        PemType::EcPrivateKey
                                    } else {
                                        PemType::EcPublicKey
                                    }
                                }
                                Classification::Rsa => {
                                    if is_private {
                                        PemType::RsaPrivateKey
                                    } else {
                                        PemType::RsaPublicKey
                                    }
                                }
                            };
                            Ok(PemEncodedKey {
                                content: pem_contents,
                                asn1: asn1_content,
                                pem_type,
                                standard: Standard::Pkcs8,
                            })
                        }
                        None => Err(ErrorKind::InvalidKeyFormat.into()),
                    },

                    // Unknown/unsupported type
                    _ => Err(ErrorKind::InvalidKeyFormat.into()),
                }
            }
            Err(_) => Err(ErrorKind::InvalidKeyFormat.into()),
        }
    }

    /// This will do the initial parsing of a PEM file.
    /// Supported tagged pems include "RSA PRIVATE KEY", "RSA PUBLIC KEY",
    /// "PRIVATE KEY", "PUBLIC KEY"
    /// PEMs with multiple tagged portions are not supported
    pub fn as_key(&self) -> Result<Key<'_>> {
        match self.standard {
            Standard::Pkcs1 => Ok(Key::Der(self.content.as_slice())),
            Standard::Pkcs8 => match self.pem_type {
                PemType::RsaPrivateKey => Ok(Key::Der(extract_first_bitstring(&self.asn1)?)),
                PemType::RsaPublicKey => Ok(Key::Der(extract_first_bitstring(&self.asn1)?)),
                PemType::EcPrivateKey => Ok(Key::Pkcs8(self.content.as_slice())),
                PemType::EcPublicKey => Ok(Key::Pkcs8(extract_first_bitstring(&self.asn1)?)),
            },
        }
    }
}

// This really just finds and returns the first bitstring or octet string
// Which is the x coordinate for EC public keys
// And the DER contents of an RSA key
// Though PKCS#11 keys shouldn't have anything else.
// It will get confusing with certificates.
fn extract_first_bitstring(asn1: &[simple_asn1::ASN1Block]) -> Result<&[u8]> {
    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Ok(result) = extract_first_bitstring(entries) {
                    return Ok(result);
                }
            }
            simple_asn1::ASN1Block::BitString(_, _, value) => {
                return Ok(value.as_ref());
            }
            simple_asn1::ASN1Block::OctetString(_, value) => {
                return Ok(value.as_ref());
            }
            _ => (),
        }
    }

    Err(ErrorKind::InvalidEcdsaKey.into())
}

/// Find whether this is EC or RSA
fn classify_pem(asn1: &[simple_asn1::ASN1Block]) -> Option<Classification> {
    // These should be constant but the macro requires
    // #![feature(const_vec_new)]
    let ec_public_key_oid = simple_asn1::oid!(1, 2, 840, 10_045, 2, 1);
    let rsa_public_key_oid = simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1);

    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Some(classification) = classify_pem(entries) {
                    return Some(classification);
                }
            }
            simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
                if oid == ec_public_key_oid {
                    return Some(Classification::Ec);
                }
                if oid == rsa_public_key_oid {
                    return Some(Classification::Rsa);
                }
            }
            _ => {}
        }
    }
    None
}
