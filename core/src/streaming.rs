//! streaming.rs — Large File Chunked AEAD Streaming & Decryption State Machine

use crate::aad;
use crate::aes_gcm::{self, NONCE_LEN, TAG_LEN};
use crate::error::{CryptoError, Result};
use crate::zeroize_types::SecureBytes;

pub const STREAM_CHUNK_OVERHEAD: usize = NONCE_LEN + TAG_LEN; // 28 bytes
pub const DEFAULT_CHUNK_PLAINTEXT: usize = 4 * 1024 * 1024; // 4 MiB

/// Encrypts one plaintext chunk into self-describing [12-byte IV][Ciphertext][16-byte Tag]
pub fn encrypt_chunk(
    key: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let nonce = aes_gcm::generate_nonce()?;
    let ciphertext = aes_gcm::encrypt(key, &nonce, plaintext, aad)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Encrypts one chunk using Protocol v1 AAD ("${chunk_index}|${total_chunks}")
pub fn encrypt_chunk_v1(
    key: &[u8],
    chunk_index: usize,
    total_chunks: usize,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let aad = aad::build_chunk_aad_v1(chunk_index, total_chunks);
    encrypt_chunk(key, plaintext, Some(&aad))
}

/// Decrypts one self-describing [12-byte IV][Ciphertext][16-byte Tag] chunk
pub fn decrypt_chunk(
    key: &[u8],
    sealed_chunk: &[u8],
    aad: Option<&[u8]>,
) -> Result<SecureBytes> {
    if sealed_chunk.len() < STREAM_CHUNK_OVERHEAD {
        return Err(CryptoError::InvalidFormat(
            "Sealed chunk shorter than nonce + tag overhead (28 bytes)".into(),
        ));
    }

    let nonce = &sealed_chunk[..NONCE_LEN];
    let ciphertext = &sealed_chunk[NONCE_LEN..];

    aes_gcm::decrypt(key, nonce, ciphertext, aad)
}

/// Decrypts one chunk using Protocol v1 AAD ("${chunk_index}|${total_chunks}")
pub fn decrypt_chunk_v1(
    key: &[u8],
    chunk_index: usize,
    total_chunks: usize,
    sealed_chunk: &[u8],
) -> Result<SecureBytes> {
    let aad = aad::build_chunk_aad_v1(chunk_index, total_chunks);
    decrypt_chunk(key, sealed_chunk, Some(&aad)).map_err(|_| {
        CryptoError::TamperingDetected(format!(
            "Chunk {} of {} failed GCM authentication check",
            chunk_index, total_chunks
        ))
    })
}

/// Decrypts a chunk whose 12-byte IV is supplied separately (e.g. ranged seek)
pub fn decrypt_chunk_with_iv(
    key: &[u8],
    iv: &[u8],
    ciphertext_and_tag: &[u8],
    aad: Option<&[u8]>,
) -> Result<SecureBytes> {
    aes_gcm::decrypt(key, iv, ciphertext_and_tag, aad)
}

/// Stateful stream validator that processes chunks in order and verifies complete-file integrity.
pub struct StreamDecryptor<'a> {
    key: &'a [u8],
    total_chunks: usize,
    expected_index: usize,
    completed: bool,
}

impl<'a> StreamDecryptor<'a> {
    pub fn new(key: &'a [u8], total_chunks: usize) -> Self {
        Self {
            key,
            total_chunks,
            expected_index: 0,
            completed: false,
        }
    }

    pub fn process_chunk(&mut self, sealed_chunk: &[u8]) -> Result<SecureBytes> {
        if self.completed {
            return Err(CryptoError::TamperingDetected(
                "Extraneous chunk received after stream completion".into(),
            ));
        }
        if self.expected_index >= self.total_chunks {
            return Err(CryptoError::TamperingDetected(
                "Stream chunk index overflow".into(),
            ));
        }

        let plaintext = decrypt_chunk_v1(
            self.key,
            self.expected_index,
            self.total_chunks,
            sealed_chunk,
        )?;

        self.expected_index += 1;
        if self.expected_index == self.total_chunks {
            self.completed = true;
        }

        Ok(plaintext)
    }

    pub fn is_finished(&self) -> bool {
        self.completed && self.expected_index == self.total_chunks
    }

    pub fn finalize(&self) -> Result<()> {
        if !self.completed || self.expected_index != self.total_chunks {
            return Err(CryptoError::TamperingDetected(format!(
                "Stream truncated: processed only {} of {} expected chunks",
                self.expected_index, self.total_chunks
            )));
        }
        Ok(())
    }
}
