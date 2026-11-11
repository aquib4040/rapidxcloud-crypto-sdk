//! hkdf.rs — HKDF-SHA256 Key Derivation & Domain Separation (RFC 5869)

use crate::error::{CryptoError, Result};
use crate::zeroize_types::{SecureBytes, SecureKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const KEY_LEN: usize = 32;

// Strictly domain-separated info strings
pub const INFO_PW_WRAP: &[u8] = b"master-wrap-password";
pub const INFO_RECOVERY_WRAP: &[u8] = b"master-wrap-recovery";
pub const INFO_FILE_ENC: &[u8] = b"file-encryption";
pub const INFO_LOGIN_AUTH: &[u8] = b"login-auth";
pub const EMAIL_SALT_PREFIX: &[u8] = b"rxc-e2e-salt-v1|";

/// HKDF-Extract followed by HKDF-Expand with SHA-256 (RFC 5869).
pub fn hkdf_derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<SecureBytes> {
    if ikm.is_empty() {
        return Err(CryptoError::InvalidParameter("IKM cannot be empty"));
    }
    if out_len == 0 || out_len > 255 * 32 {
        return Err(CryptoError::InvalidParameter("Invalid HKDF output length"));
    }

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::InvalidParameter("HKDF expand output length exceeds limit"))?;

    Ok(SecureBytes::new(okm))
}

/// Derives a 32-byte key via HKDF with optional salt.
pub fn hkdf_derive_32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<SecureKey<KEY_LEN>> {
    let bytes = hkdf_derive(ikm, salt, info, KEY_LEN)?;
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(SecureKey::new(out))
}

/// Computes SHA-256 digest of input.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes deterministic 16-byte account salt from user email.
/// Matches WebCrypto: SHA-256("rxc-e2e-salt-v1|" + email.trim().to_lowercase())[0..16].
pub fn salt_for_email(email: &str) -> [u8; 16] {
    let norm = email.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(EMAIL_SALT_PREFIX);
    hasher.update(norm.as_bytes());
    let full = hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&full[0..16]);
    salt
}
