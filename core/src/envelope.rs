//! envelope.rs — Master Secret Key Envelope Encryption & Decryption

use crate::aes_gcm;
use crate::error::{CryptoError, Result};
use crate::hkdf::{self, KEY_LEN};
use crate::kdf::{self, KDFProfile};
use crate::recovery;
use crate::zeroize_types::SecureKey;
use base64ct::{Base64, Encoding};

pub const WRAP_INFO_PW: &str = "master-wrap-password";
pub const WRAP_INFO_RECOVERY: &str = "master-wrap-recovery";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSecret {
    pub data: String, // Base64 [12B IV][Ciphertext][16B Tag]
    pub salt: String, // Base64 16-byte salt
}

impl WrappedSecret {
    pub fn new(data: String, salt: String) -> Self {
        Self { data, salt }
    }

    /// Serializes to JSON string: {"data":"...","salt":"..."}
    pub fn to_json(&self) -> String {
        format!(r#"{{"data":"{}","salt":"{}"}}"#, self.data, self.salt)
    }

    /// Parses from JSON string {"data":"...","salt":"..."}
    pub fn from_json(json: &str) -> Result<Self> {
        let extract = |field: &str| -> Option<String> {
            let pattern = format!(r#""{}":""#, field);
            let start = json.find(&pattern)? + pattern.len();
            let end = json[start..].find('"')? + start;
            Some(json[start..end].to_string())
        };

        let data = extract("data")
            .ok_or_else(|| CryptoError::InvalidFormat("Missing 'data' field in envelope".into()))?;
        let salt = extract("salt")
            .ok_or_else(|| CryptoError::InvalidFormat("Missing 'salt' field in envelope".into()))?;

        Ok(Self { data, salt })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBag {
    pub wrapped_pw: WrappedSecret,
    pub wrapped_recovery: WrappedSecret,
}

impl KeyBag {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"wrapped_pw":{},"wrapped_recovery":{}}}"#,
            self.wrapped_pw.to_json(),
            self.wrapped_recovery.to_json()
        )
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let extract_obj = |field: &str| -> Option<&str> {
            let pattern = format!(r#""{}":{{"#, field);
            let start = json.find(&pattern)? + pattern.len() - 1;
            let end = json[start..].find('}')? + start + 1;
            Some(&json[start..end])
        };

        let pw_str = extract_obj("wrapped_pw").ok_or_else(|| {
            CryptoError::InvalidFormat("Missing 'wrapped_pw' in keybag JSON".into())
        })?;
        let rec_str = extract_obj("wrapped_recovery").ok_or_else(|| {
            CryptoError::InvalidFormat("Missing 'wrapped_recovery' in keybag JSON".into())
        })?;

        Ok(Self {
            wrapped_pw: WrappedSecret::from_json(pw_str)?,
            wrapped_recovery: WrappedSecret::from_json(rec_str)?,
        })
    }
}

/// Derives wrap key from secret, salt, and HKDF info tag.
pub fn derive_wrap_key(secret: &str, salt: &[u8], info: &str) -> Result<SecureKey<KEY_LEN>> {
    let mk = kdf::derive_key_profile(secret.as_bytes(), salt, KDFProfile::Interactive64MB)?;
    hkdf::hkdf_derive_32(mk.as_slice(), None, info.as_bytes())
}

/// Wraps Master Secret M under a secret string using AES-256-GCM.
pub fn wrap_master(master_secret: &[u8], secret: &str, info: &str) -> Result<WrappedSecret> {
    if master_secret.len() != KEY_LEN {
        return Err(CryptoError::InvalidParameter(
            "Master secret must be 32 bytes",
        ));
    }
    let salt = kdf::generate_salt(16)?;
    let wrap_key = derive_wrap_key(secret, &salt, info)?;
    let nonce = aes_gcm::generate_nonce()?;

    let ciphertext = aes_gcm::encrypt(wrap_key.as_slice(), &nonce, master_secret, None)?;

    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);

    Ok(WrappedSecret {
        data: Base64::encode_string(&sealed),
        salt: Base64::encode_string(&salt),
    })
}

/// Unwraps Master Secret M using secret string and HKDF info tag.
pub fn unwrap_master(
    wrapped: &WrappedSecret,
    secret: &str,
    info: &str,
) -> Result<SecureKey<KEY_LEN>> {
    let salt = Base64::decode_vec(&wrapped.salt)
        .map_err(|e| CryptoError::InvalidFormat(format!("Salt base64 invalid: {}", e)))?;
    let sealed = Base64::decode_vec(&wrapped.data)
        .map_err(|e| CryptoError::InvalidFormat(format!("Data base64 invalid: {}", e)))?;

    if sealed.len() < aes_gcm::NONCE_LEN + aes_gcm::TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }

    let nonce = &sealed[..aes_gcm::NONCE_LEN];
    let ciphertext = &sealed[aes_gcm::NONCE_LEN..];

    let wrap_key = derive_wrap_key(secret, &salt, info)?;
    let plaintext = aes_gcm::decrypt(wrap_key.as_slice(), nonce, ciphertext, None)?;

    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidFormat(
            "Unwrapped master key wrong length".into(),
        ));
    }

    let mut m = [0u8; KEY_LEN];
    m.copy_from_slice(plaintext.as_slice());
    Ok(SecureKey::new(m))
}

/// Complete account enrollment: generates M, wraps under password and recovery code, returns KeyBag.
pub fn enroll_master(password: &str) -> Result<(SecureKey<KEY_LEN>, KeyBag, String)> {
    let m = aes_gcm::generate_key()?;
    let recovery_code = recovery::generate_recovery_code()?;
    let norm_code = recovery::normalize_recovery_code(&recovery_code);

    let wrapped_pw = wrap_master(m.as_slice(), password, WRAP_INFO_PW)?;
    let wrapped_recovery = wrap_master(m.as_slice(), &norm_code, WRAP_INFO_RECOVERY)?;

    let enc_key = crate::master_secret::derive_enc_key(m.as_slice())?;

    let key_bag = KeyBag {
        wrapped_pw,
        wrapped_recovery,
    };

    Ok((enc_key, key_bag, recovery_code))
}

/// Unlocks KeyBag using account password.
pub fn unlock_with_password(
    key_bag: &KeyBag,
    password: &str,
) -> Result<(SecureKey<KEY_LEN>, SecureKey<KEY_LEN>)> {
    let m = unwrap_master(&key_bag.wrapped_pw, password, WRAP_INFO_PW)?;
    let enc_key = crate::master_secret::derive_enc_key(m.as_slice())?;
    Ok((enc_key, m))
}

/// Recovers Master Secret M using Recovery Key, and re-wraps M under new password.
pub fn recover_with_code(
    key_bag: &KeyBag,
    recovery_code: &str,
    new_password: &str,
) -> Result<(SecureKey<KEY_LEN>, WrappedSecret, SecureKey<KEY_LEN>)> {
    let norm_code = recovery::normalize_recovery_code(recovery_code);
    let m = unwrap_master(&key_bag.wrapped_recovery, &norm_code, WRAP_INFO_RECOVERY)?;
    let new_wrapped_pw = wrap_master(m.as_slice(), new_password, WRAP_INFO_PW)?;
    let enc_key = crate::master_secret::derive_enc_key(m.as_slice())?;
    Ok((enc_key, new_wrapped_pw, m))
}
