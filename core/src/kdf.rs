//! kdf.rs — Argon2id Password-Based Key Derivation (RFC 9106)

use crate::error::{CryptoError, Result};
use crate::zeroize_types::{SecureBytes, SecureKey};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const MIN_SALT_LEN: usize = 16;
pub const DEFAULT_SALT_LEN: usize = 32;

// Strict DoS upper limits on KDF parameters
pub const MAX_KDF_MEMORY_KIB: u32 = 1_048_576; // 1 GiB
pub const MAX_KDF_ITERATIONS: u32 = 20;
pub const MAX_KDF_PARALLELISM: u32 = 16;
pub const MIN_KDF_MEMORY_KIB: u32 = 1_024; // 1 MiB minimum
pub const MIN_KDF_ITERATIONS: u32 = 1;
pub const MIN_KDF_OUT_LEN: usize = 16;
pub const MAX_KDF_OUT_LEN: usize = 1024;

/// Versioned KDF Profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KDFProfile {
    /// 256 MiB memory, t=3, p=4 (High-end Android & Desktop)
    Production256MB,
    /// 64 MiB memory, t=3, p=1 (Default for RapidxCloud Mobile & Web)
    Interactive64MB,
    /// 512 MiB memory, t=4, p=4 (High Security Vault)
    HighSecurity512MB,
    /// 1 MiB memory, t=1, p=1 (Test only)
    TestFast,
}

impl KDFProfile {
    pub fn memory_kib(&self) -> u32 {
        match self {
            KDFProfile::Production256MB => 262_144,   // 256 MiB
            KDFProfile::Interactive64MB => 65_536,    // 64 MiB
            KDFProfile::HighSecurity512MB => 524_288, // 512 MiB
            KDFProfile::TestFast => 1_024,            // 1 MiB
        }
    }

    pub fn iterations(&self) -> u32 {
        match self {
            KDFProfile::Production256MB => 3,
            KDFProfile::Interactive64MB => 3,
            KDFProfile::HighSecurity512MB => 4,
            KDFProfile::TestFast => 1,
        }
    }

    pub fn parallelism(&self) -> u32 {
        match self {
            KDFProfile::Production256MB => 4,
            KDFProfile::Interactive64MB => 1,
            KDFProfile::HighSecurity512MB => 4,
            KDFProfile::TestFast => 1,
        }
    }

    pub fn profile_name(&self) -> &'static str {
        match self {
            KDFProfile::Production256MB => "production-256mb",
            KDFProfile::Interactive64MB => "interactive-64mb",
            KDFProfile::HighSecurity512MB => "high-security-512mb",
            KDFProfile::TestFast => "test-fast",
        }
    }
}

/// Generates fresh cryptographically secure random salt.
pub fn generate_salt(len: usize) -> Result<Vec<u8>> {
    if len < MIN_SALT_LEN {
        return Err(CryptoError::InvalidParameter(
            "Salt length must be at least 16 bytes",
        ));
    }
    let mut salt = vec![0u8; len];
    getrandom::getrandom(&mut salt).map_err(|_| CryptoError::EntropyError)?;
    Ok(salt)
}

/// Validates KDF parameters against strict denial-of-service bounds.
pub fn validate_kdf_params(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    out_len: usize,
) -> Result<()> {
    if !(MIN_KDF_MEMORY_KIB..=MAX_KDF_MEMORY_KIB).contains(&memory_kib) {
        return Err(CryptoError::KdfError(format!(
            "Memory cost {} KiB outside safe bounds [{}, {}]",
            memory_kib, MIN_KDF_MEMORY_KIB, MAX_KDF_MEMORY_KIB
        )));
    }
    if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&iterations) {
        return Err(CryptoError::KdfError(format!(
            "Iterations {} outside safe bounds [{}, {}]",
            iterations, MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS
        )));
    }
    if !(1..=MAX_KDF_PARALLELISM).contains(&parallelism) {
        return Err(CryptoError::KdfError(format!(
            "Parallelism {} outside safe bounds [1, {}]",
            parallelism, MAX_KDF_PARALLELISM
        )));
    }
    if !(MIN_KDF_OUT_LEN..=MAX_KDF_OUT_LEN).contains(&out_len) {
        return Err(CryptoError::KdfError(format!(
            "Output length {} outside safe bounds [{}, {}]",
            out_len, MIN_KDF_OUT_LEN, MAX_KDF_OUT_LEN
        )));
    }
    Ok(())
}

/// Derives a key using Argon2id with zeroized intermediate buffers.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    out_len: usize,
) -> Result<SecureBytes> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CryptoError::InvalidParameter(
            "Salt length must be at least 16 bytes",
        ));
    }
    validate_kdf_params(memory_kib, iterations, parallelism, out_len)?;

    let params = Params::new(memory_kib, iterations, parallelism, Some(out_len))
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len];

    // If password is valid UTF-8, normalize to NFC so that decomposed characters
    // (e.g. macOS NFD vs Windows/Linux NFC) produce identical keys across platforms.
    let res = if let Ok(s) = core::str::from_utf8(password) {
        use unicode_normalization::UnicodeNormalization;
        let mut norm: String = s.nfc().collect();
        let r = argon2.hash_password_into(norm.as_bytes(), salt, &mut out);
        norm.zeroize();
        r
    } else {
        argon2.hash_password_into(password, salt, &mut out)
    };

    if let Err(e) = res {
        out.zeroize();
        return Err(CryptoError::KdfError(e.to_string()));
    }

    Ok(SecureBytes::new(out))
}

/// Derives a 32-byte key using a standard KDFProfile.
pub fn derive_key_profile(
    password: &[u8],
    salt: &[u8],
    profile: KDFProfile,
) -> Result<SecureKey<KEY_LEN>> {
    let raw = derive_key(
        password,
        salt,
        profile.memory_kib(),
        profile.iterations(),
        profile.parallelism(),
        KEY_LEN,
    )?;

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw);
    Ok(SecureKey::new(key))
}
