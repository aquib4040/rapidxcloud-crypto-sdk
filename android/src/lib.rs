//! canondrive_crypto — Android Native & C-FFI Bridge
//! Uses shared rapidxcloud-crypto-core with JNI and FFI exports.

pub mod ffi;
pub mod jni;

pub use rapidxcloud_crypto_core::*;
