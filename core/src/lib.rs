//! rapidxcloud-crypto-core — Pure Rust, Memory-Safe Cryptographic Engine
//! Consolidated cryptographic core for Android Native and WebAssembly (WASM).

pub mod aad;
pub mod aes_gcm;
pub mod envelope;
pub mod error;
pub mod hkdf;
pub mod kdf;
pub mod manifest;
pub mod master_secret;
pub mod mtproto;
pub mod recovery;
pub mod split;
pub mod streaming;
pub mod zeroize_types;

// Top-level re-exports
pub use aad::{build_chunk_aad_v1, build_strict_chunk_aad_v2, PROTOCOL_V1, PROTOCOL_V2};
pub use aes_gcm::{
    decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt, generate_key, generate_nonce,
    KEY_LEN as AES_KEY_LEN, NONCE_LEN, TAG_LEN,
};
pub use envelope::{
    enroll_master, recover_with_code, unlock_with_password, unwrap_master, wrap_master, KeyBag,
    WrappedSecret, WRAP_INFO_PW, WRAP_INFO_RECOVERY,
};
pub use error::{CryptoError, Result};
pub use hkdf::{
    hkdf_derive, hkdf_derive_32, salt_for_email, sha256_digest, INFO_FILE_ENC, INFO_LOGIN_AUTH,
    INFO_PW_WRAP, INFO_RECOVERY_WRAP,
};
pub use kdf::{
    derive_key as argon2id_derive, derive_key_profile, generate_salt, validate_kdf_params,
    KDFProfile, DEFAULT_SALT_LEN, MIN_SALT_LEN,
};
pub use manifest::{FileManifest, ManifestChunk, DEFAULT_CHUNK_SIZE};
pub use master_secret::{derive_enc_key, generate_master_secret};
pub use recovery::{generate_recovery_code, normalize_recovery_code, RECOVERY_ALPHABET};
pub use split::{
    combine_shares, seal_client_share, split_key, unseal_client_share, xor_shares, SHARE_LEN,
};
pub use streaming::{
    decrypt_chunk, decrypt_chunk_v1, decrypt_chunk_with_iv, encrypt_chunk, encrypt_chunk_v1,
    StreamDecryptor, DEFAULT_CHUNK_PLAINTEXT, STREAM_CHUNK_OVERHEAD,
};
pub use zeroize_types::{SecureBytes, SecureKey};

// WASM custom entropy registration
#[cfg(target_arch = "wasm32")]
mod wasm_entropy {
    #[link(wasm_import_module = "env")]
    extern "C" {
        fn host_getrandom(buf: *mut u8, len: usize) -> i32;
    }

    fn custom_getrandom(buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
        let ret = unsafe { host_getrandom(buf.as_mut_ptr(), buf.len()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(getrandom::Error::UNEXPECTED)
        }
    }

    getrandom::register_custom_getrandom!(custom_getrandom);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        let key = generate_key().unwrap();
        let nonce = generate_nonce().unwrap();
        let plaintext = b"Hello, RapidxCloud Zero-Knowledge Storage!";
        let aad = b"chunk-aad-0-10";

        let ciphertext = aes_gcm_encrypt(key.as_slice(), &nonce, plaintext, Some(aad)).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);

        let decrypted = aes_gcm_decrypt(key.as_slice(), &nonce, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let key = generate_key().unwrap();
        let nonce = generate_nonce().unwrap();
        let plaintext = b"Confidential document content";
        let aad = b"valid-aad";

        let mut ciphertext = aes_gcm_encrypt(key.as_slice(), &nonce, plaintext, Some(aad)).unwrap();

        // 1. Alter ciphertext byte
        ciphertext[0] ^= 0x55;
        let res = aes_gcm_decrypt(key.as_slice(), &nonce, &ciphertext, Some(aad));
        assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));

        // Restore ciphertext
        ciphertext[0] ^= 0x55;

        // 2. Alter AAD
        let wrong_aad = b"tampered-aad";
        let res = aes_gcm_decrypt(key.as_slice(), &nonce, &ciphertext, Some(wrong_aad));
        assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));

        // 3. Alter nonce
        let mut tampered_nonce = nonce;
        tampered_nonce[0] ^= 0x01;
        let res = aes_gcm_decrypt(key.as_slice(), &tampered_nonce, &ciphertext, Some(aad));
        assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_argon2id_kdf_and_unicode_nfc() {
        let salt = b"deterministic16b";

        // Test unicode NFC normalization: 'é' composed vs decomposed
        let pw_composed = "café";
        let pw_decomposed = "cafe\u{0301}";

        let key1 = argon2id_derive(pw_composed.as_bytes(), salt, 16384, 2, 1, 32).unwrap();
        let key2 = argon2id_derive(pw_decomposed.as_bytes(), salt, 16384, 2, 1, 32).unwrap();
        assert_eq!(key1.as_slice(), key2.as_slice());

        // Rejection of invalid parameters
        assert!(validate_kdf_params(0, 1, 1, 32).is_err());
        assert!(validate_kdf_params(65536, 0, 1, 32).is_err());
        assert!(validate_kdf_params(65536, 1, 0, 32).is_err());
        assert!(validate_kdf_params(65536, 1, 1, 15).is_err());
    }

    #[test]
    fn test_email_salt_compatibility() {
        let email = "User@Example.COM ";
        let salt = salt_for_email(email);
        assert_eq!(salt.len(), 16);

        // Must match lowercase trimmed: "user@example.com"
        let salt2 = salt_for_email("user@example.com");
        assert_eq!(salt, salt2);

        // Verification of salt prefix format SHA256("rxc-e2e-salt-v1|" + email)[..16]
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"rxc-e2e-salt-v1|user@example.com");
        let expected = &h.finalize()[..16];
        assert_eq!(salt.as_slice(), expected);
    }

    #[test]
    fn test_master_secret_enroll_unlock_recovery() {
        let password = "SuperSecretPassword123!";
        let (enc_key, key_bag, recovery_code) = enroll_master(password).unwrap();
        assert_eq!(enc_key.len(), 32);

        // Unlock with password
        let (unlocked_enc_key, _) = unlock_with_password(&key_bag, password).unwrap();
        assert_eq!(enc_key.as_slice(), unlocked_enc_key.as_slice());

        // Wrong password fails
        let fail_res = unlock_with_password(&key_bag, "WrongPassword");
        assert!(fail_res.is_err());

        // Recover with code (including lowercase and ambiguous character substitutions)
        let (recovered_enc_key, _, _) =
            recover_with_code(&key_bag, &recovery_code, "NewPass987!").unwrap();
        assert_eq!(enc_key.as_slice(), recovered_enc_key.as_slice());

        // Ambiguous lowercase test (e.g. replacing '0' with 'o' or 'O')
        let altered_code = recovery_code.replace('0', "o").to_lowercase();
        let (recovered_altered, _, _) =
            recover_with_code(&key_bag, &altered_code, "AnotherPass11!").unwrap();
        assert_eq!(enc_key.as_slice(), recovered_altered.as_slice());
    }

    #[test]
    fn test_recovery_code_normalization() {
        assert_eq!(normalize_recovery_code("abcd-1234"), "ABCD1234");
        assert_eq!(normalize_recovery_code("ab-cd 12-34"), "ABCD1234");
        // Crockford Base32: 'O', 'o' -> '0', 'I', 'i', 'L', 'l' -> '1'
        assert_eq!(normalize_recovery_code("O1Il"), "0111");
        assert_eq!(normalize_recovery_code("o0"), "00");
    }

    #[test]
    fn test_dual_key_split_and_reconstruction() {
        let file_key = generate_key().unwrap();
        let (server_share, client_share) = split_key(file_key.as_slice()).unwrap();

        // Neither share equals the file key
        assert_ne!(server_share.as_slice(), file_key.as_slice());
        assert_ne!(client_share.as_slice(), file_key.as_slice());

        // Information theoretic reconstruction
        let reconstructed =
            combine_shares(client_share.as_slice(), server_share.as_slice()).unwrap();
        assert_eq!(reconstructed.as_slice(), file_key.as_slice());

        // Seal / unseal client share under encKey
        let enc_key = generate_key().unwrap();
        let sealed = seal_client_share(
            enc_key.as_slice(),
            client_share.as_slice(),
            Some(b"file-123"),
        )
        .unwrap();
        assert_eq!(sealed.len(), 12 + 32 + 16); // 60 bytes

        let unsealed = unseal_client_share(enc_key.as_slice(), &sealed, Some(b"file-123")).unwrap();
        assert_eq!(unsealed.as_slice(), client_share.as_slice());

        // Unseal with wrong AAD fails
        assert!(unseal_client_share(enc_key.as_slice(), &sealed, Some(b"file-999")).is_err());
    }

    #[test]
    fn test_streaming_chunk_encryption_and_v1_aad() {
        let key = generate_key().unwrap();
        let plaintext = vec![0x42u8; 1024]; // 1 KB chunk
        let chunk_index = 2;
        let total_chunks = 5;

        // V1 encryption
        let sealed =
            encrypt_chunk_v1(key.as_slice(), chunk_index, total_chunks, &plaintext).unwrap();
        assert_eq!(sealed.len(), 12 + 1024 + 16);

        // V1 decryption with correct index & total
        let decrypted =
            decrypt_chunk_v1(key.as_slice(), chunk_index, total_chunks, &sealed).unwrap();
        assert_eq!(decrypted.as_slice(), &plaintext[..]);

        // Decryption fails if chunk index or total chunks is swapped (anti-splicing protection)
        let swap_idx = decrypt_chunk_v1(key.as_slice(), 3, total_chunks, &sealed);
        assert!(swap_idx.is_err());

        let swap_total = decrypt_chunk_v1(key.as_slice(), chunk_index, 6, &sealed);
        assert!(swap_total.is_err());
    }

    #[test]
    fn test_stream_decryptor_state_machine() {
        let key = generate_key().unwrap();
        let chunks_plain = [
            b"First chunk data...".to_vec(),
            b"Second chunk data...".to_vec(),
            b"Third chunk data...".to_vec(),
        ];
        let total_chunks = chunks_plain.len();

        let mut sealed_chunks = Vec::new();
        for (idx, p) in chunks_plain.iter().enumerate() {
            let s = encrypt_chunk_v1(key.as_slice(), idx, total_chunks, p).unwrap();
            sealed_chunks.push(s);
        }

        // Sequential processing
        let mut decryptor = StreamDecryptor::new(key.as_slice(), total_chunks);
        for (idx, s) in sealed_chunks.iter().enumerate() {
            let pt = decryptor.process_chunk(s).unwrap();
            assert_eq!(pt.as_slice(), chunks_plain[idx].as_slice());
        }
        assert!(decryptor.is_finished());
        assert!(decryptor.finalize().is_ok());

        // Processing additional chunk after completion fails
        assert!(decryptor.process_chunk(&sealed_chunks[0]).is_err());

        // Out-of-order rejection
        let mut bad_decryptor = StreamDecryptor::new(key.as_slice(), total_chunks);
        assert!(bad_decryptor.process_chunk(&sealed_chunks[1]).is_err()); // passed chunk 1 instead of chunk 0
    }

    #[test]
    fn test_cancellation_registry() {
        let slot_a = 42;
        let slot_b = 42 + 64; // Collided in older modulo-64 implementation!

        assert!(!mtproto::is_transfer_cancelled(slot_a));
        assert!(!mtproto::is_transfer_cancelled(slot_b));

        // Cancel slot_a
        mtproto::set_transfer_cancelled(slot_a, true);
        assert!(mtproto::is_transfer_cancelled(slot_a));
        assert!(!mtproto::is_transfer_cancelled(slot_b)); // slot_b MUST NOT be cancelled!

        // Cancel slot_b
        mtproto::set_transfer_cancelled(slot_b, true);
        assert!(mtproto::is_transfer_cancelled(slot_a));
        assert!(mtproto::is_transfer_cancelled(slot_b));

        // Clear slot_a
        mtproto::set_transfer_cancelled(slot_a, false);
        assert!(!mtproto::is_transfer_cancelled(slot_a));
        assert!(mtproto::is_transfer_cancelled(slot_b)); // slot_b remains cancelled

        mtproto::set_transfer_cancelled(slot_b, false);
        assert!(!mtproto::is_transfer_cancelled(slot_b));
    }

    #[test]
    fn test_telethon_session_parsing_and_auth_key_id() {
        // Construct a synthetic 263-byte IPv4 Telethon v1 session
        let mut raw = Vec::new();
        raw.push(2u8); // DC ID = 2
        raw.extend_from_slice(&[149, 154, 167, 51]); // IP: 149.154.167.51
        raw.extend_from_slice(&443u16.to_be_bytes()); // Port: 443
        let auth_key = vec![0x77u8; 256]; // 256-byte auth key
        raw.extend_from_slice(&auth_key);

        // Encode as URL-safe Base64 without padding prefixed with '1'
        use base64ct::{Base64UrlUnpadded, Encoding};
        let b64 = Base64UrlUnpadded::encode_string(&raw);
        let session_str = format!("1{}", b64);

        let parsed = mtproto::parse_telethon_session(&session_str);
        assert!(parsed.is_some());
        let (dc_id, ip, port, parsed_auth_key, auth_key_id) = parsed.unwrap();
        assert_eq!(dc_id, 2);
        assert_eq!(ip, "149.154.167.51");
        assert_eq!(port, 443);
        assert_eq!(parsed_auth_key, auth_key);

        let expected_key_id = mtproto::compute_auth_key_id(&auth_key).unwrap();
        assert_eq!(auth_key_id, expected_key_id);
    }
}
