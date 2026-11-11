//! rapidxcloud_crypto — Android Native & C-FFI Bridge
//! Uses shared rapidxcloud-crypto-core with JNI and FFI exports.

#![allow(clippy::missing_safety_doc)]

pub mod ffi;
pub mod jni;

pub use rapidxcloud_crypto_core::*;
