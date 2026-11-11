//! manifest.rs — Authenticated File Manifest Generation & Verification

use crate::error::{CryptoError, Result};
use crate::hkdf;
use aes_gcm::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
pub const ALGORITHM_AES_256_GCM: &str = "AES-256-GCM";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestChunk {
    pub index: usize,
    pub plain_start: u64,
    pub plain_end: u64,
    pub cipher_start: u64,
    pub cipher_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    pub version: u8,
    pub file_uuid: String,
    pub generation_id: String,
    pub algorithm: String,
    pub total_size: u64,
    pub chunk_plaintext: usize,
    pub total_chunks: usize,
    pub chunks: Vec<ManifestChunk>,
    pub mac: String, // Hex HMAC-SHA256 over canonical manifest fields
}

impl FileManifest {
    /// Computes HMAC over canonical manifest metadata using the file key
    pub fn compute_mac(
        file_key: &[u8],
        version: u8,
        file_uuid: &str,
        generation_id: &str,
        total_size: u64,
        total_chunks: usize,
    ) -> Result<String> {
        let mac_key = hkdf::hkdf_derive_32(file_key, None, b"manifest-mac")?;
        let mut mac = HmacSha256::new_from_slice(mac_key.as_slice())
            .map_err(|_| CryptoError::InvalidParameter("HMAC key length invalid"))?;

        let canonical = format!(
            "rxc-manifest:{}:{}:{}:{}:{}",
            version, file_uuid, generation_id, total_size, total_chunks
        );
        mac.update(canonical.as_bytes());
        let result = mac.finalize().into_bytes();

        let mut hex = String::with_capacity(64);
        for b in result {
            use core::fmt::Write;
            write!(&mut hex, "{:02x}", b).unwrap();
        }
        Ok(hex)
    }

    /// Creates and signs a new v2 manifest
    pub fn create_v2(
        file_key: &[u8],
        file_uuid: &str,
        generation_id: &str,
        total_size: u64,
        chunk_size: usize,
    ) -> Result<Self> {
        let chunk_plain = if chunk_size > 0 {
            chunk_size
        } else {
            DEFAULT_CHUNK_SIZE
        };
        let total_chunks = if total_size == 0 {
            1
        } else {
            ((total_size + chunk_plain as u64 - 1) / chunk_plain as u64) as usize
        };

        let mut chunks = Vec::with_capacity(total_chunks);
        let mut plain_offset: u64 = 0;
        let mut cipher_offset: u64 = 0;

        for i in 0..total_chunks {
            let chunk_len = if total_size == 0 {
                0
            } else {
                core::cmp::min(chunk_plain as u64, total_size - plain_offset)
            };
            let plain_start = plain_offset;
            let plain_end = if chunk_len == 0 {
                0
            } else {
                plain_start + chunk_len - 1
            };
            let cipher_len = chunk_len + 12 + 16; // 12-byte IV + ciphertext + 16-byte Tag
            let cipher_start = cipher_offset;
            let cipher_end = cipher_start + cipher_len - 1;

            chunks.push(ManifestChunk {
                index: i,
                plain_start,
                plain_end,
                cipher_start,
                cipher_end,
            });

            plain_offset += chunk_len;
            cipher_offset += cipher_len;
        }

        let mac = Self::compute_mac(
            file_key,
            2,
            file_uuid,
            generation_id,
            total_size,
            total_chunks,
        )?;

        Ok(Self {
            version: 2,
            file_uuid: file_uuid.to_string(),
            generation_id: generation_id.to_string(),
            algorithm: ALGORITHM_AES_256_GCM.to_string(),
            total_size,
            chunk_plaintext: chunk_plain,
            total_chunks,
            chunks,
            mac,
        })
    }

    /// Verifies manifest integrity against the file key and chunks
    pub fn verify(&self, file_key: &[u8]) -> Result<()> {
        if self.version == 2 {
            let expected_mac = Self::compute_mac(
                file_key,
                self.version,
                &self.file_uuid,
                &self.generation_id,
                self.total_size,
                self.total_chunks,
            )?;

            if self.mac.to_lowercase() != expected_mac.to_lowercase() {
                return Err(CryptoError::ManifestMismatch(
                    "Manifest HMAC signature verification failed".into(),
                ));
            }
        }

        if self.chunks.len() != self.total_chunks {
            return Err(CryptoError::ManifestMismatch(format!(
                "Manifest chunk count mismatch: expected {}, got {}",
                self.total_chunks,
                self.chunks.len()
            )));
        }

        // Verify sequential continuity
        let mut expected_plain: u64 = 0;
        let mut expected_cipher: u64 = 0;

        for (i, c) in self.chunks.iter().enumerate() {
            if c.index != i {
                return Err(CryptoError::ManifestMismatch(format!(
                    "Chunk index non-sequential at {}",
                    i
                )));
            }
            if c.plain_start != expected_plain {
                return Err(CryptoError::ManifestMismatch(format!(
                    "Chunk {} plain_start mismatch: expected {}, got {}",
                    i, expected_plain, c.plain_start
                )));
            }
            if c.cipher_start != expected_cipher {
                return Err(CryptoError::ManifestMismatch(format!(
                    "Chunk {} cipher_start mismatch: expected {}, got {}",
                    i, expected_cipher, c.cipher_start
                )));
            }

            let plain_len = if self.total_size == 0 {
                0
            } else {
                c.plain_end - c.plain_start + 1
            };
            let cipher_len = c.cipher_end - c.cipher_start + 1;
            if cipher_len != plain_len + 28 {
                return Err(CryptoError::ManifestMismatch(format!(
                    "Chunk {} invalid cipher overhead: plain {} vs cipher {}",
                    i, plain_len, cipher_len
                )));
            }

            expected_plain += plain_len;
            expected_cipher += cipher_len;
        }

        if expected_plain != self.total_size {
            return Err(CryptoError::ManifestMismatch(format!(
                "Manifest total size mismatch: expected {}, got {}",
                self.total_size, expected_plain
            )));
        }

        Ok(())
    }
}
