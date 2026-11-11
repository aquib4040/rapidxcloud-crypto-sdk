//! mtproto.rs — Telegram MTProto Session Parsing & Framing Utilities

use crate::error::{CryptoError, Result};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use sha1::{Digest as Sha1Digest, Sha1};
use std::collections::HashMap;
use std::sync::RwLock;
use zeroize::Zeroize;

/// Dynamic thread-safe cancellation registry replacing fixed modulo-64 array
static CANCELLATION_REGISTRY: RwLock<Option<HashMap<i32, bool>>> = RwLock::new(None);

pub fn set_transfer_cancelled(slot_id: i32, cancelled: bool) {
    let mut lock = CANCELLATION_REGISTRY.write().unwrap();
    let map = lock.get_or_insert_with(HashMap::new);
    if cancelled {
        map.insert(slot_id, true);
    } else {
        map.remove(&slot_id);
    }
}

pub fn is_transfer_cancelled(slot_id: i32) -> bool {
    let lock = CANCELLATION_REGISTRY.read().unwrap();
    if let Some(map) = lock.as_ref() {
        map.get(&slot_id).copied().unwrap_or(false)
    } else {
        false
    }
}

pub const MTPROTO_UPLOAD_CHUNK_BYTES: usize = 512 * 1024; // 512 KiB
pub const TEN_MEGABYTES: i64 = 10 * 1024 * 1024;

/// Computes lower 64 bits of SHA-1 hash as little-endian i64 (Telegram MTProto specification)
pub fn compute_auth_key_id(auth_key: &[u8]) -> Result<i64> {
    if auth_key.len() != 256 {
        return Err(CryptoError::InvalidParameter(
            "MTProto auth_key must be exactly 256 bytes",
        ));
    }
    let mut hasher = Sha1::new();
    hasher.update(auth_key);
    let result = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[12..20]);
    Ok(i64::from_le_bytes(bytes))
}

/// Parses Python Telethon session string (supports both standard and URL-safe Base64, padded or unpadded).
/// Returns: (dc_id, ip_address, port, auth_key, auth_key_id)
pub fn parse_telethon_session(session: &str) -> Option<(i32, String, i32, Vec<u8>, i64)> {
    let trimmed = session.trim();
    if !trimmed.starts_with('1') {
        return None;
    }

    let payload = &trimmed[1..];
    let unpadded_payload = payload.trim_end_matches('=');

    // Try URL-safe unpadded first (standard Telethon v1 format), then standard Base64
    let mut decoded = Base64UrlUnpadded::decode_vec(unpadded_payload)
        .or_else(|_| Base64::decode_vec(payload))
        .ok()?;

    if decoded.len() < 263 {
        decoded.zeroize();
        return None;
    }

    let dc_id = decoded[0] as i32;
    let is_ipv6 = decoded.len() >= 275;
    let mut pos = 1;

    let ip_address = if !is_ipv6 {
        let ip = format!(
            "{}.{}.{}.{}",
            decoded[1], decoded[2], decoded[3], decoded[4]
        );
        pos = 5;
        ip
    } else {
        let mut groups = Vec::new();
        for i in (0..16).step_by(2) {
            let val = ((decoded[pos + i] as u16) << 8) | (decoded[pos + i + 1] as u16);
            groups.push(format!("{:x}", val));
        }
        pos += 16;
        groups.join(":")
    };

    let port = (((decoded[pos] as u16) << 8) | (decoded[pos + 1] as u16)) as i32;
    pos += 2;

    if pos + 256 > decoded.len() {
        decoded.zeroize();
        return None;
    }

    let auth_key = decoded[pos..pos + 256].to_vec();
    decoded.zeroize();

    let auth_key_id = compute_auth_key_id(&auth_key).ok()?;

    Some((dc_id, ip_address, port, auth_key, auth_key_id))
}
