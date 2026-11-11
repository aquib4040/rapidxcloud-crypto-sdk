//! rapidxcloud-crypto-wasm — Pure WebAssembly Bridge for Browser E2EE Operations
#![allow(clippy::missing_safety_doc)]

use core::slice;
use rapidxcloud_crypto_core::aes_gcm::{self, NONCE_LEN, TAG_LEN};
use rapidxcloud_crypto_core::envelope::{self, WrappedSecret};
use rapidxcloud_crypto_core::error::CryptoError;
use rapidxcloud_crypto_core::hkdf::{self, KEY_LEN};
use rapidxcloud_crypto_core::kdf;
use rapidxcloud_crypto_core::manifest::FileManifest;
use rapidxcloud_crypto_core::master_secret;
use rapidxcloud_crypto_core::recovery;
use rapidxcloud_crypto_core::split::{self, SHARE_LEN};
use rapidxcloud_crypto_core::streaming;

pub const RXC_OK: i32 = 0;
pub const RXC_ERR_AUTH_FAILED: i32 = -1;
pub const RXC_ERR_INVALID_PARAM: i32 = -2;
pub const RXC_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const RXC_ERR_CRYPTO_FAILED: i32 = -4;
pub const RXC_ERR_FORMAT: i32 = -5;

// ── WASM Linear Memory Allocator ──────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn wasm_alloc(size: usize) -> *mut u8 {
    let total_len = size + 8;
    let layout = std::alloc::Layout::from_size_align_unchecked(total_len, 8);
    let raw = std::alloc::alloc(layout);
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    *(raw as *mut usize) = total_len;
    raw.add(8)
}

#[no_mangle]
pub unsafe extern "C" fn wasm_free(ptr: *mut u8, _size: usize) {
    if ptr.is_null() {
        return;
    }
    let raw = ptr.sub(8);
    let total_len = *(raw as *const usize);
    let layout = std::alloc::Layout::from_size_align_unchecked(total_len, 8);
    std::alloc::dealloc(raw, layout);
}

#[no_mangle]
pub unsafe extern "C" fn wasm_free_zeroize(ptr: *mut u8, _size: usize) {
    if ptr.is_null() {
        return;
    }
    let raw = ptr.sub(8);
    let total_len = *(raw as *const usize);
    let user_len = total_len - 8;
    std::ptr::write_bytes(ptr, 0, user_len);
    let layout = std::alloc::Layout::from_size_align_unchecked(total_len, 8);
    std::alloc::dealloc(raw, layout);
}

// ── KDF & HKDF ───────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_argon2id(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    if password_ptr.is_null() || salt_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let password = slice::from_raw_parts(password_ptr, password_len);
    let salt = slice::from_raw_parts(salt_ptr, salt_len);
    let out = slice::from_raw_parts_mut(out_ptr, out_len);

    match kdf::derive_key(password, salt, memory_kb, iterations, parallelism, out_len) {
        Ok(derived) => {
            out.copy_from_slice(&derived);
            RXC_OK
        }
        Err(CryptoError::KdfError(_)) => RXC_ERR_CRYPTO_FAILED,
        Err(_) => RXC_ERR_INVALID_PARAM,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_hkdf_expand(
    ikm_ptr: *const u8,
    ikm_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    if ikm_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let ikm = slice::from_raw_parts(ikm_ptr, ikm_len);
    let info = if info_len > 0 && !info_ptr.is_null() {
        slice::from_raw_parts(info_ptr, info_len)
    } else {
        &[]
    };
    let out = slice::from_raw_parts_mut(out_ptr, out_len);

    match hkdf::hkdf_derive(ikm, None, info, out_len) {
        Ok(derived) => {
            out.copy_from_slice(&derived);
            RXC_OK
        }
        Err(_) => RXC_ERR_INVALID_PARAM,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_salt_for_email(
    email_ptr: *const u8,
    email_len: usize,
    out_ptr: *mut u8, // must be at least 16 bytes
) -> i32 {
    if email_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let email_slice = slice::from_raw_parts(email_ptr, email_len);
    let email = match core::str::from_utf8(email_slice) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };

    let salt = hkdf::salt_for_email(email);
    let out = slice::from_raw_parts_mut(out_ptr, 16);
    out.copy_from_slice(&salt);
    RXC_OK
}

// ── Master Secret & Key Envelope ──────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_generate_master_secret(out_ptr: *mut u8) -> i32 {
    if out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    match master_secret::generate_master_secret() {
        Ok(m) => {
            let out = slice::from_raw_parts_mut(out_ptr, KEY_LEN);
            out.copy_from_slice(m.as_slice());
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_derive_enc_key(m_ptr: *const u8, out_ptr: *mut u8) -> i32 {
    if m_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    let m = slice::from_raw_parts(m_ptr, KEY_LEN);
    match master_secret::derive_enc_key(m) {
        Ok(enc_key) => {
            let out = slice::from_raw_parts_mut(out_ptr, KEY_LEN);
            out.copy_from_slice(enc_key.as_slice());
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_wrap_master(
    m_ptr: *const u8,
    secret_ptr: *const u8,
    secret_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if m_ptr.is_null() || secret_ptr.is_null() || out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let m = slice::from_raw_parts(m_ptr, KEY_LEN);
    let secret = match core::str::from_utf8(slice::from_raw_parts(secret_ptr, secret_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };
    let info = match core::str::from_utf8(slice::from_raw_parts(info_ptr, info_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };

    match envelope::wrap_master(m, secret, info) {
        Ok(wrapped) => {
            let json = wrapped.to_json();
            let bytes = json.as_bytes();
            if bytes.len() > out_max {
                return RXC_ERR_BUFFER_TOO_SMALL;
            }
            let out = slice::from_raw_parts_mut(out_buf, bytes.len());
            out.copy_from_slice(bytes);
            *out_written = bytes.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_unwrap_master(
    data_ptr: *const u8,
    data_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    secret_ptr: *const u8,
    secret_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    out_ptr: *mut u8, // must be 32 bytes
) -> i32 {
    if data_ptr.is_null() || salt_ptr.is_null() || secret_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let data = match core::str::from_utf8(slice::from_raw_parts(data_ptr, data_len)) {
        Ok(s) => s.to_string(),
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };
    let salt = match core::str::from_utf8(slice::from_raw_parts(salt_ptr, salt_len)) {
        Ok(s) => s.to_string(),
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };
    let secret = match core::str::from_utf8(slice::from_raw_parts(secret_ptr, secret_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };
    let info = match core::str::from_utf8(slice::from_raw_parts(info_ptr, info_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };

    let wrapped = WrappedSecret::new(data, salt);
    match envelope::unwrap_master(&wrapped, secret, info) {
        Ok(m) => {
            let out = slice::from_raw_parts_mut(out_ptr, KEY_LEN);
            out.copy_from_slice(m.as_slice());
            RXC_OK
        }
        Err(CryptoError::AuthenticationFailed) => RXC_ERR_AUTH_FAILED,
        Err(CryptoError::InvalidFormat(_)) => RXC_ERR_FORMAT,
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

// ── Recovery Code ─────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_generate_recovery_code(
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    match recovery::generate_recovery_code() {
        Ok(code) => {
            let bytes = code.as_bytes();
            if bytes.len() > out_max {
                return RXC_ERR_BUFFER_TOO_SMALL;
            }
            let out = slice::from_raw_parts_mut(out_buf, bytes.len());
            out.copy_from_slice(bytes);
            *out_written = bytes.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_normalize_recovery_code(
    in_ptr: *const u8,
    in_len: usize,
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if in_ptr.is_null() || out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let code_str = match core::str::from_utf8(slice::from_raw_parts(in_ptr, in_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };

    let norm = recovery::normalize_recovery_code(code_str);
    let bytes = norm.as_bytes();
    if bytes.len() > out_max {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }
    let out = slice::from_raw_parts_mut(out_buf, bytes.len());
    out.copy_from_slice(bytes);
    *out_written = bytes.len();
    RXC_OK
}

// ── Key Split & Reconstruction ───────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_generate_file_key(out_ptr: *mut u8) -> i32 {
    if out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    match aes_gcm::generate_key() {
        Ok(k) => {
            let out = slice::from_raw_parts_mut(out_ptr, SHARE_LEN);
            out.copy_from_slice(k.as_slice());
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_split_file_key(
    file_key_ptr: *const u8,
    server_share_out: *mut u8,
    client_share_out: *mut u8,
) -> i32 {
    if file_key_ptr.is_null() || server_share_out.is_null() || client_share_out.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let file_key = slice::from_raw_parts(file_key_ptr, SHARE_LEN);
    match split::split_key(file_key) {
        Ok((server_share, client_share)) => {
            let s_out = slice::from_raw_parts_mut(server_share_out, SHARE_LEN);
            let c_out = slice::from_raw_parts_mut(client_share_out, SHARE_LEN);
            s_out.copy_from_slice(server_share.as_slice());
            c_out.copy_from_slice(client_share.as_slice());
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_combine_shares(
    client_share_ptr: *const u8,
    server_share_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    if client_share_ptr.is_null() || server_share_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let client_share = slice::from_raw_parts(client_share_ptr, SHARE_LEN);
    let server_share = slice::from_raw_parts(server_share_ptr, SHARE_LEN);

    match split::combine_shares(client_share, server_share) {
        Ok(file_key) => {
            let out = slice::from_raw_parts_mut(out_ptr, SHARE_LEN);
            out.copy_from_slice(file_key.as_slice());
            RXC_OK
        }
        Err(_) => RXC_ERR_INVALID_PARAM,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_seal_client_share(
    enc_key_ptr: *const u8,
    client_share_ptr: *const u8,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8, // must be at least 60 bytes (12 IV + 32 CT + 16 Tag)
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if enc_key_ptr.is_null()
        || client_share_ptr.is_null()
        || out_buf.is_null()
        || out_written.is_null()
    {
        return RXC_ERR_INVALID_PARAM;
    }

    let enc_key = slice::from_raw_parts(enc_key_ptr, KEY_LEN);
    let client_share = slice::from_raw_parts(client_share_ptr, SHARE_LEN);
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    match split::seal_client_share(enc_key, client_share, aad) {
        Ok(sealed) => {
            if sealed.len() > out_max {
                return RXC_ERR_BUFFER_TOO_SMALL;
            }
            let out = slice::from_raw_parts_mut(out_buf, sealed.len());
            out.copy_from_slice(&sealed);
            *out_written = sealed.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_unseal_client_share(
    enc_key_ptr: *const u8,
    sealed_ptr: *const u8,
    sealed_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_ptr: *mut u8, // must be 32 bytes
) -> i32 {
    if enc_key_ptr.is_null() || sealed_ptr.is_null() || out_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let enc_key = slice::from_raw_parts(enc_key_ptr, KEY_LEN);
    let sealed = slice::from_raw_parts(sealed_ptr, sealed_len);
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    match split::unseal_client_share(enc_key, sealed, aad) {
        Ok(share) => {
            let out = slice::from_raw_parts_mut(out_ptr, SHARE_LEN);
            out.copy_from_slice(share.as_slice());
            RXC_OK
        }
        Err(CryptoError::AuthenticationFailed) => RXC_ERR_AUTH_FAILED,
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

// ── Chunk AEAD Operations ────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_encrypt_chunk(
    key_ptr: *const u8,
    pt_ptr: *const u8,
    pt_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null() || out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    if pt_len > 0 && pt_ptr.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let key = slice::from_raw_parts(key_ptr, KEY_LEN);
    let plaintext = if pt_len > 0 {
        slice::from_raw_parts(pt_ptr, pt_len)
    } else {
        &[]
    };
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    let required = pt_len + NONCE_LEN + TAG_LEN;
    if out_max < required {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }

    match streaming::encrypt_chunk(key, plaintext, aad) {
        Ok(sealed) => {
            let out = slice::from_raw_parts_mut(out_buf, sealed.len());
            out.copy_from_slice(&sealed);
            *out_written = sealed.len();
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_decrypt_chunk(
    key_ptr: *const u8,
    sealed_ptr: *const u8,
    sealed_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null() || sealed_ptr.is_null() || out_buf.is_null() || out_written.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }
    if sealed_len < NONCE_LEN + TAG_LEN {
        return RXC_ERR_INVALID_PARAM;
    }

    let key = slice::from_raw_parts(key_ptr, KEY_LEN);
    let sealed = slice::from_raw_parts(sealed_ptr, sealed_len);
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    let required = sealed_len - (NONCE_LEN + TAG_LEN);
    if out_max < required {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }

    match streaming::decrypt_chunk(key, sealed, aad) {
        Ok(pt) => {
            let out = slice::from_raw_parts_mut(out_buf, pt.len());
            out.copy_from_slice(&pt);
            *out_written = pt.len();
            RXC_OK
        }
        Err(CryptoError::AuthenticationFailed) | Err(CryptoError::TamperingDetected(_)) => {
            RXC_ERR_AUTH_FAILED
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rxc_decrypt_chunk_with_iv(
    key_ptr: *const u8,
    iv_ptr: *const u8,
    ct_ptr: *const u8,
    ct_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buf: *mut u8,
    out_max: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null()
        || iv_ptr.is_null()
        || ct_ptr.is_null()
        || out_buf.is_null()
        || out_written.is_null()
    {
        return RXC_ERR_INVALID_PARAM;
    }
    if ct_len < TAG_LEN {
        return RXC_ERR_INVALID_PARAM;
    }

    let key = slice::from_raw_parts(key_ptr, KEY_LEN);
    let iv = slice::from_raw_parts(iv_ptr, NONCE_LEN);
    let ct = slice::from_raw_parts(ct_ptr, ct_len);
    let aad = if aad_len > 0 && !aad_ptr.is_null() {
        Some(slice::from_raw_parts(aad_ptr, aad_len))
    } else {
        None
    };

    let required = ct_len - TAG_LEN;
    if out_max < required {
        return RXC_ERR_BUFFER_TOO_SMALL;
    }

    match streaming::decrypt_chunk_with_iv(key, iv, ct, aad) {
        Ok(pt) => {
            let out = slice::from_raw_parts_mut(out_buf, pt.len());
            out.copy_from_slice(&pt);
            *out_written = pt.len();
            RXC_OK
        }
        Err(CryptoError::AuthenticationFailed) | Err(CryptoError::TamperingDetected(_)) => {
            RXC_ERR_AUTH_FAILED
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}

// ── Authenticated Manifest ───────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rxc_compute_manifest_mac(
    file_key_ptr: *const u8,
    version: u8,
    uuid_ptr: *const u8,
    uuid_len: usize,
    gen_id_ptr: *const u8,
    gen_id_len: usize,
    total_size: u64,
    total_chunks: usize,
    out_buf: *mut u8, // must be 64 bytes
) -> i32 {
    if file_key_ptr.is_null() || uuid_ptr.is_null() || gen_id_ptr.is_null() || out_buf.is_null() {
        return RXC_ERR_INVALID_PARAM;
    }

    let file_key = slice::from_raw_parts(file_key_ptr, KEY_LEN);
    let uuid = match core::str::from_utf8(slice::from_raw_parts(uuid_ptr, uuid_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };
    let gen_id = match core::str::from_utf8(slice::from_raw_parts(gen_id_ptr, gen_id_len)) {
        Ok(s) => s,
        Err(_) => return RXC_ERR_INVALID_PARAM,
    };

    match FileManifest::compute_mac(file_key, version, uuid, gen_id, total_size, total_chunks) {
        Ok(mac_hex) => {
            let bytes = mac_hex.as_bytes();
            let out = slice::from_raw_parts_mut(out_buf, 64);
            out.copy_from_slice(&bytes[..64]);
            RXC_OK
        }
        Err(_) => RXC_ERR_CRYPTO_FAILED,
    }
}
