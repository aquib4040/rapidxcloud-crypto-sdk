//! ffi.rs — Cross-Platform C-ABI Foreign Function Interface (FFI)

use rapidxcloud_crypto_core::aes_gcm;
use rapidxcloud_crypto_core::error::CryptoError;
use rapidxcloud_crypto_core::kdf;
use std::slice;
use zeroize::Zeroize;

pub const RXC_OK: i32 = 0;
pub const RXC_ERR_AUTH_FAILED: i32 = -1;
pub const RXC_ERR_INVALID_PARAM: i32 = -2;
pub const RXC_ERR_KDF_FAILED: i32 = -3;
pub const RXC_ERR_BUFFER_TOO_SMALL: i32 = -4;

/// Computes Argon2id KDF: writes out_len bytes into out_buf.
#[no_mangle]
pub unsafe extern "C" fn rxc_argon2id(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    out_buf: *mut u8,
    out_len: usize,
) -> i32 {
    if password_ptr.is_null() || salt_ptr.is_null() || out_buf.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let password = slice::from_raw_parts(password_ptr, password_len);
    let salt = slice::from_raw_parts(salt_ptr, salt_len);
    let out_slice = slice::from_raw_parts_mut(out_buf, out_len);

    match kdf::derive_key(
        password,
        salt,
        memory_kib,
        iterations,
        parallelism,
        out_len,
    ) {
        Ok(derived) => {
            out_slice.copy_from_slice(&derived);
            RXC_OK
        }
        Err(CryptoError::KdfError(_)) => RXC_ERR_KDF_FAILED,
        Err(_) => RXC_ERR_INVALID_PARAM,
    }
}

/// AES-256-GCM Encrypt: out_buf must be at least plaintext_len + 16 (tag)
/// Fixes CRITICAL-05: properly rejects NULL plaintext_ptr when plaintext_len > 0
#[no_mangle]
pub unsafe extern "C" fn rxc_aes_gcm_encrypt(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null() || nonce_ptr.is_null() || out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    if key_len != 32 || nonce_len != 12 {
        return RXC_ERR_INVALID_PARAM;
    }
    // CRITICAL-05 fix: Fail closed if pointer is null but length > 0
    if plaintext_len > 0 && plaintext_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let key = slice::from_raw_parts(key_ptr, key_len);
    let nonce = slice::from_raw_parts(nonce_ptr, nonce_len);
    let plaintext = if plaintext_len > 0 {
        slice::from_raw_parts(plaintext_ptr, plaintext_len)
    } else {
        &[]
    };
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    let required_len = match plaintext.len().checked_add(16) {
        Some(l) => l,
        None => return RXC_ERR_INVALID_PARAM,
    };
    if out_buf_len < required_len {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }

    match aes_gcm::encrypt(key, nonce, plaintext, aad) {
        Ok(ct) => {
            let out_slice = slice::from_raw_parts_mut(out_buf, ct.len());
            out_slice.copy_from_slice(&ct);
            *out_written = ct.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_AUTH_FAILED,
    }
}

/// AES-256-GCM Decrypt
#[no_mangle]
pub unsafe extern "C" fn rxc_aes_gcm_decrypt(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null()
        || nonce_ptr.is_null()
        || ciphertext_ptr.is_null()
        || out_buf.is_null()
        || out_written.is_null()
    {
        return RXC_ERR_INVALID_PARAM;
    }
    if key_len != 32 || nonce_len != 12 || ciphertext_len < 16 {
        return RXC_ERR_INVALID_PARAM;
    }

    let key = slice::from_raw_parts(key_ptr, key_len);
    let nonce = slice::from_raw_parts(nonce_ptr, nonce_len);
    let ciphertext = slice::from_raw_parts(ciphertext_ptr, ciphertext_len);
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    let expected_plaintext_len = ciphertext_len - 16;
    if out_buf_len < expected_plaintext_len {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }

    match aes_gcm::decrypt(key, nonce, ciphertext, aad) {
        Ok(pt) => {
            let out_slice = slice::from_raw_parts_mut(out_buf, pt.len());
            out_slice.copy_from_slice(&pt);
            *out_written = pt.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_AUTH_FAILED,
    }
}

/// XOR two 32-byte key shares with explicit alias/overlap safety
#[no_mangle]
pub unsafe extern "C" fn rxc_xor_shares(
    share_a_ptr: *const u8,
    share_b_ptr: *const u8,
    out_buf: *mut u8,
    len: usize,
) -> i32 {
    if share_a_ptr.is_null() || share_b_ptr.is_null() || out_buf.is_null() || len != 32 {
        return RXC_ERR_INVALID_PARAM;
    }

    // Check for partial overlaps that would cause corrupted reads/writes
    let a_start = share_a_ptr as usize;
    let b_start = share_b_ptr as usize;
    let out_start = out_buf as usize;

    let partial_overlap = |p1: usize, p2: usize| -> bool {
        if p1 == p2 {
            false // Exact in-place aliasing is handled via stack staging
        } else {
            p1 < p2 + len && p2 < p1 + len
        }
    };

    if partial_overlap(out_start, a_start) || partial_overlap(out_start, b_start) {
        return RXC_ERR_INVALID_PARAM;
    }

    // Read byte-by-byte into a stack buffer to guarantee no Rust mutable reference aliasing
    let mut tmp = [0u8; 32];
    for i in 0..32 {
        tmp[i] = *share_a_ptr.add(i) ^ *share_b_ptr.add(i);
    }

    core::ptr::copy_nonoverlapping(tmp.as_ptr(), out_buf, 32);
    tmp.zeroize();
    RXC_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_null_pointer_rejection() {
        unsafe {
            assert_eq!(
                rxc_argon2id(std::ptr::null(), 0, std::ptr::null(), 0, 1024, 1, 1, std::ptr::null_mut(), 32),
                RXC_ERR_INVALID_PARAM
            );

            let mut out = [0u8; 32];
            let mut written = 0;
            assert_eq!(
                rxc_aes_gcm_encrypt(std::ptr::null(), 32, std::ptr::null(), 12, std::ptr::null(), 10, std::ptr::null(), 0, out.as_mut_ptr(), 32, &mut written),
                RXC_ERR_INVALID_PARAM
            );

            assert_eq!(
                rxc_xor_shares(std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), 32),
                RXC_ERR_INVALID_PARAM
            );
        }
    }

    #[test]
    fn test_ffi_xor_shares_inplace_and_aliasing() {
        unsafe {
            let mut share_a = [0xAAu8; 32];
            let share_b = [0x55u8; 32];

            // In-place XOR into share_a: 0xAA ^ 0x55 = 0xFF
            let res = rxc_xor_shares(share_a.as_ptr(), share_b.as_ptr(), share_a.as_mut_ptr(), 32);
            assert_eq!(res, RXC_OK);
            assert_eq!(share_a, [0xFFu8; 32]);

            // Partial overlap check: buffer of 64 bytes with 16 byte offset
            let mut big_buf = [0u8; 64];
            let a_ptr = big_buf.as_ptr();
            let b_ptr = big_buf.as_ptr().add(32);
            let overlapping_out = big_buf.as_mut_ptr().add(16); // partially overlaps both!

            let bad_res = rxc_xor_shares(a_ptr, b_ptr, overlapping_out, 32);
            assert_eq!(bad_res, RXC_ERR_INVALID_PARAM);
        }
    }

    #[test]
    fn test_ffi_aes_gcm_roundtrip() {
        unsafe {
            let key = [0x42u8; 32];
            let nonce = [0x11u8; 12];
            let plaintext = b"Hello FFI!";
            let aad = b"aad-context";

            let mut cipher_buf = [0u8; 64];
            let mut cipher_len = 0;

            let enc_res = rxc_aes_gcm_encrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
                cipher_buf.as_mut_ptr(),
                cipher_buf.len(),
                &mut cipher_len,
            );
            assert_eq!(enc_res, RXC_OK);
            assert_eq!(cipher_len, plaintext.len() + 16);

            let mut plain_buf = [0u8; 64];
            let mut plain_len = 0;

            let dec_res = rxc_aes_gcm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                cipher_buf.as_ptr(),
                cipher_len,
                aad.as_ptr(),
                aad.len(),
                plain_buf.as_mut_ptr(),
                plain_buf.len(),
                &mut plain_len,
            );
            assert_eq!(dec_res, RXC_OK);
            assert_eq!(&plain_buf[..plain_len], plaintext);

            // Authentication failure on tampered ciphertext
            cipher_buf[0] ^= 0x01;
            let fail_res = rxc_aes_gcm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                cipher_buf.as_ptr(),
                cipher_len,
                aad.as_ptr(),
                aad.len(),
                plain_buf.as_mut_ptr(),
                plain_buf.len(),
                &mut plain_len,
            );
            assert_eq!(fail_res, RXC_ERR_AUTH_FAILED);
        }
    }
}
