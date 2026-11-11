//! split.rs — Dual-Key Split (Defense-in-Depth Zero-Knowledge Key Separation)
//! Information-Theoretic One-Time Pad: FileKey = ServerShare ⊕ ClientShare

use crate::aes_gcm::{self, NONCE_LEN, TAG_LEN};
use crate::error::{CryptoError, Result};
use crate::zeroize_types::SecureKey;

pub const SHARE_LEN: usize = 32;

/// Constant-time bitwise XOR of two 32-byte key shares.
pub fn xor_shares_32(a: &[u8; SHARE_LEN], b: &[u8; SHARE_LEN]) -> SecureKey<SHARE_LEN> {
    let mut out = [0u8; SHARE_LEN];
    for i in 0..SHARE_LEN {
        out[i] = a[i] ^ b[i];
    }
    SecureKey::new(out)
}

/// Constant-time bitwise XOR of two dynamic key slices.
pub fn xor_shares(a: &[u8], b: &[u8]) -> Result<SecureKey<SHARE_LEN>> {
    if a.len() != SHARE_LEN || b.len() != SHARE_LEN {
        return Err(CryptoError::InvalidParameter("Shares must be exactly 32 bytes"));
    }
    let a_arr: &[u8; SHARE_LEN] = a.try_into().unwrap();
    let b_arr: &[u8; SHARE_LEN] = b.try_into().unwrap();
    Ok(xor_shares_32(a_arr, b_arr))
}

/// Splits a 32-byte raw FileKey into ServerShare (random) and ClientShare (FileKey ⊕ ServerShare).
pub fn split_key(file_key: &[u8]) -> Result<(SecureKey<SHARE_LEN>, SecureKey<SHARE_LEN>)> {
    if file_key.len() != SHARE_LEN {
        return Err(CryptoError::InvalidParameter("File key must be 32 bytes"));
    }
    let server_share = aes_gcm::generate_key()?;
    let key_arr: &[u8; SHARE_LEN] = file_key.try_into().unwrap();
    let client_share = xor_shares_32(key_arr, &server_share);

    Ok((server_share, client_share))
}

/// Recombines ClientShare and ServerShare to recover original FileKey.
pub fn combine_shares(client_share: &[u8], server_share: &[u8]) -> Result<SecureKey<SHARE_LEN>> {
    xor_shares(client_share, server_share)
}

/// Seals the ClientShare using user's encKey with AES-256-GCM.
/// Emits self-describing [12-byte IV][32-byte Ciphertext][16-byte Tag] (total 60 bytes).
pub fn seal_client_share(
    enc_key: &[u8],
    client_share: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if client_share.len() != SHARE_LEN {
        return Err(CryptoError::InvalidParameter("ClientShare must be 32 bytes"));
    }
    let nonce = aes_gcm::generate_nonce()?;
    let ciphertext = aes_gcm::encrypt(enc_key, &nonce, client_share, aad)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Unseals the ClientShare from sealed bytes using user's encKey.
pub fn unseal_client_share(
    enc_key: &[u8],
    sealed_share: &[u8],
    aad: Option<&[u8]>,
) -> Result<SecureKey<SHARE_LEN>> {
    if sealed_share.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidFormat("Sealed client share too short".into()));
    }
    let nonce = &sealed_share[..NONCE_LEN];
    let ciphertext = &sealed_share[NONCE_LEN..];

    let plaintext = aes_gcm::decrypt(enc_key, nonce, ciphertext, aad)?;
    if plaintext.len() != SHARE_LEN {
        return Err(CryptoError::InvalidFormat("Unsealed client share wrong length".into()));
    }

    let mut share = [0u8; SHARE_LEN];
    share.copy_from_slice(&plaintext);
    Ok(SecureKey::new(share))
}
