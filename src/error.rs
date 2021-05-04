use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct Error {
    /// Debug message associated with error
    pub msg: &'static str,
    pub kind: ErrorKind,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for Error {}

/// Type of error encountered
#[derive(Debug)]
pub enum ErrorKind {
    /// An error decoding or validating a token
    JwtDecodeError(Box<jsonwebtoken::errors::ErrorKind>),
    /// Problem with key
    Key,
    /// Could not download key set
    Connection,
    /// Unsupported key type, only RSA is currently supported
    UnsupportedKeyType(crate::keyset::JsonWebKeyTypes),
    /// Algorithm mismatch - algorithm of token doesn't match intended algorithm of key
    AlgorithmMismatch,
    /// No remote store specified to fetch from in key_url
    NoRemoteStore,
    /// No algorithm specified
    NoAlgorithm,
    /// No key ID specified
    NoKeyId,
    /// Internal problem (Signals a serious bug or fatal error)
    Internal,
}

pub(crate) fn err(msg: &'static str, kind: ErrorKind) -> Error {
    Error { msg, kind }
}

pub(crate) fn err_key(msg: &'static str) -> Error {
    err(msg, ErrorKind::Key)
}

pub(crate) fn err_con(msg: &'static str) -> Error {
    err(msg, ErrorKind::Connection)
}

pub(crate) fn err_int(msg: &'static str) -> Error {
    err(msg, ErrorKind::Internal)
}

pub(crate) fn err_jwt(error: jsonwebtoken::errors::Error) -> Error {
    err("", ErrorKind::JwtDecodeError(Box::new(error.into_kind())))
}

#[cfg(test)]
mod tests {}
