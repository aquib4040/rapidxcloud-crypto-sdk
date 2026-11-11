//! recovery.rs — Crockford-32 Alphanumeric Recovery Key Generation & Normalization

use crate::error::{CryptoError, Result};
use zeroize::Zeroize;

pub const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Generates human-friendly 160-bit alphanumeric emergency recovery code
/// formatted as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (32 Crockford Base32 characters)
pub fn generate_recovery_code() -> Result<String> {
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes).map_err(|_| CryptoError::EntropyError)?;

    let mut out = String::with_capacity(39);
    for i in 0..32 {
        let idx = (random_bytes[i] as usize) & 31;
        out.push(RECOVERY_ALPHABET[idx] as char);
        if i % 5 == 4 && i != 31 {
            out.push('-');
        }
    }
    random_bytes.zeroize();
    Ok(out)
}

/// Normalizes recovery code:
/// - Strips whitespace, hyphens, and formatting characters
/// - Converts to uppercase
/// - Translates ambiguous characters per Crockford Base32:
///   'O' / 'o' -> '0'
///   'I' / 'i' / 'L' / 'l' -> '1'
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter_map(|c| match c {
            '-' | ' ' | '_' | '\t' | '\r' | '\n' => None,
            'O' | 'o' => Some('0'),
            'I' | 'i' | 'L' | 'l' => Some('1'),
            c if c.is_ascii_alphanumeric() => Some(c.to_ascii_uppercase()),
            _ => None,
        })
        .collect()
}

