//! jni.rs — Android JNI Native Interface Bindings
//! Exposes NativeCrypto methods to Java/Kotlin in in.rapidxcloud.drive.crypto.NativeCrypto

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong};
use jni::JNIEnv;
use grammers_tl_types as tl;
use rapidxcloud_crypto_core::aes_gcm;
use rapidxcloud_crypto_core::hkdf;
use rapidxcloud_crypto_core::kdf;
use rapidxcloud_crypto_core::mtproto::{self, MTPROTO_UPLOAD_CHUNK_BYTES};
use rapidxcloud_crypto_core::split;
use rapidxcloud_crypto_core::streaming;
use tl::Serializable;

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_isNativeAvailable(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    1
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_setCancelled(
    _env: JNIEnv,
    _class: JClass,
    slot_id: jint,
    cancelled: jboolean,
) {
    mtproto::set_transfer_cancelled(slot_id, cancelled != 0);
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_isCancelled(
    _env: JNIEnv,
    _class: JClass,
    slot_id: jint,
) -> jboolean {
    if mtproto::is_transfer_cancelled(slot_id) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_argon2id(
    mut env: JNIEnv,
    _class: JClass,
    password: JString,
    salt: JByteArray,
    memory_kb: jint,
    iterations: jint,
    parallelism: jint,
    out_len: jint,
) -> jbyteArray {
    let password_str: String = match env.get_string(&password) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let salt_bytes = match env.convert_byte_array(&salt) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let out_len_usize = if out_len > 0 { out_len as usize } else { 32 };

    let derived = match kdf::derive_key(
        password_str.as_bytes(),
        &salt_bytes,
        memory_kb as u32,
        iterations as u32,
        parallelism as u32,
        out_len_usize,
    ) {
        Ok(d) => d,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array = match env.byte_array_from_slice(&derived) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    byte_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_hkdfExpand(
    env: JNIEnv,
    _class: JClass,
    ikm: JByteArray,
    info: JByteArray,
    out_length: jint,
) -> jbyteArray {
    let ikm_bytes = match env.convert_byte_array(&ikm) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let info_bytes = match env.convert_byte_array(&info) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let out_len = if out_length > 0 {
        out_length as usize
    } else {
        32
    };

    let okm = match hkdf::hkdf_derive(&ikm_bytes, None, &info_bytes, out_len) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array = match env.byte_array_from_slice(&okm) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    byte_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_xorShares(
    env: JNIEnv,
    _class: JClass,
    share_a: JByteArray,
    share_b: JByteArray,
) -> jbyteArray {
    let a_bytes = match env.convert_byte_array(&share_a) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let b_bytes = match env.convert_byte_array(&share_b) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let out = match split::xor_shares(&a_bytes, &b_bytes) {
        Ok(x) => x,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array = match env.byte_array_from_slice(out.as_slice()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    byte_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_aesGcmEncrypt(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    nonce: JByteArray,
    plaintext: JByteArray,
    aad: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_bytes = match env.convert_byte_array(&nonce) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let pt_bytes = match env.convert_byte_array(&plaintext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let aad_bytes = if !aad.is_null() {
        match env.convert_byte_array(&aad) {
            Ok(b) => Some(b),
            Err(_) => None,
        }
    } else {
        None
    };

    let ct = match aes_gcm::encrypt(
        &key_bytes,
        &nonce_bytes,
        &pt_bytes,
        aad_bytes.as_deref(),
    ) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array = match env.byte_array_from_slice(&ct) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    byte_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_aesGcmDecrypt(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    nonce: JByteArray,
    ciphertext: JByteArray,
    aad: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_bytes = match env.convert_byte_array(&nonce) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let ct_bytes = match env.convert_byte_array(&ciphertext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let aad_bytes = if !aad.is_null() {
        match env.convert_byte_array(&aad) {
            Ok(b) => Some(b),
            Err(_) => None,
        }
    } else {
        None
    };

    let pt = match aes_gcm::decrypt(
        &key_bytes,
        &nonce_bytes,
        &ct_bytes,
        aad_bytes.as_deref(),
    ) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array = match env.byte_array_from_slice(&pt) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    byte_array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_validateChunkPart(
    _env: JNIEnv,
    _class: JClass,
    part_size: jint,
    part_index: jint,
    total_parts: jint,
) -> jboolean {
    if part_size <= 0 || part_size > MTPROTO_UPLOAD_CHUNK_BYTES as jint {
        return 0;
    }
    if part_index < 0 || total_parts <= 0 || part_index >= total_parts {
        return 0;
    }
    1
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_validateSessionString(
    mut env: JNIEnv,
    _class: JClass,
    session_str: JString,
) -> jboolean {
    let session: String = match env.get_string(&session_str) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    if mtproto::parse_telethon_session(&session).is_some() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_parseTelethonSession(
    mut env: JNIEnv,
    _class: JClass,
    session_str: JString,
) -> jlong {
    let session: String = match env.get_string(&session_str) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    match mtproto::parse_telethon_session(&session) {
        Some((_, _, _, _, auth_key_id)) => auth_key_id,
        None => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_frameUploadPart(
    env: JNIEnv,
    _class: JClass,
    file_id: jlong,
    part_index: jint,
    total_parts: jint,
    total_file_size: jlong,
    chunk: JByteArray,
) -> jbyteArray {
    let chunk_bytes = match env.convert_byte_array(&chunk) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    if chunk_bytes.is_empty() || chunk_bytes.len() > MTPROTO_UPLOAD_CHUNK_BYTES {
        return std::ptr::null_mut();
    }
    if part_index < 0 || total_parts <= 0 || part_index >= total_parts {
        return std::ptr::null_mut();
    }

    let framed = if total_file_size < rapidxcloud_crypto_core::mtproto::TEN_MEGABYTES {
        let req = tl::functions::upload::SaveFilePart {
            file_id,
            file_part: part_index,
            bytes: chunk_bytes,
        };
        req.to_bytes()
    } else {
        let req = tl::functions::upload::SaveBigFilePart {
            file_id,
            file_part: part_index,
            file_total_parts: total_parts,
            bytes: chunk_bytes,
        };
        req.to_bytes()
    };

    match env.byte_array_from_slice(&framed) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_encryptStreamChunk(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    plaintext: JByteArray,
    aad: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let pt_bytes = match env.convert_byte_array(&plaintext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let aad_bytes = if !aad.is_null() {
        env.convert_byte_array(&aad).ok()
    } else {
        None
    };

    let sealed = match streaming::encrypt_chunk(
        &key_bytes,
        &pt_bytes,
        aad_bytes.as_deref(),
    ) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&sealed) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_in_rapidxcloud_drive_crypto_NativeCrypto_decryptStreamChunk(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    sealed_chunk: JByteArray,
    aad: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let sealed_bytes = match env.convert_byte_array(&sealed_chunk) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let aad_bytes = if !aad.is_null() {
        env.convert_byte_array(&aad).ok()
    } else {
        None
    };

    let pt = match streaming::decrypt_chunk(
        &key_bytes,
        &sealed_bytes,
        aad_bytes.as_deref(),
    ) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(pt.as_slice()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
