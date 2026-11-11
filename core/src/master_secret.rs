//! master_secret.rs — 32-Byte Master Secret Management

use crate::aes_gcm;
use crate::error::Result;
use crate::hkdf::{self, INFO_FILE_ENC, KEY_LEN};
use crate::zeroize_types::SecureKey;

/// Generates fresh random 32-byte Master Secret M.
pub fn generate_master_secret() -> Result<SecureKey<KEY_LEN>> {
    aes_gcm::generate_key()
}

/// Derives the stable 32-byte file encryption key (`encKey`) from Master Secret M.
pub fn derive_enc_key(master_secret: &[u8]) -> Result<SecureKey<KEY_LEN>> {
    hkdf::hkdf_derive_32(master_secret, None, INFO_FILE_ENC)
}
