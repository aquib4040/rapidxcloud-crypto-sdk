//! error.rs — Cryptographic Error Types with Safe Constant-Time Fail-Closed Semantics

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    AuthenticationFailed,
    EntropyError,
    InvalidParameter(&'static str),
    KdfError(String),
    InvalidFormat(String),
    TamperingDetected(String),
    EncryptionFailure,
    ManifestMismatch(String),
    BufferTooSmall,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::AuthenticationFailed => {
                write!(f, "Cryptographic authentication check failed")
            }
            CryptoError::EntropyError => {
                write!(f, "Cryptographically secure random generation failed")
            }
            CryptoError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            CryptoError::KdfError(msg) => write!(f, "Key derivation failed: {}", msg),
            CryptoError::InvalidFormat(msg) => write!(f, "Invalid cryptographic format: {}", msg),
            CryptoError::TamperingDetected(msg) => {
                write!(f, "Integrity tampering detected: {}", msg)
            }
            CryptoError::EncryptionFailure => write!(f, "Authenticated encryption failed"),
            CryptoError::ManifestMismatch(msg) => write!(f, "Manifest verification failed: {}", msg),
            CryptoError::BufferTooSmall => write!(f, "Destination buffer too small"),
        }
    }
}

pub type Result<T> = core::result::Result<T, CryptoError>;
