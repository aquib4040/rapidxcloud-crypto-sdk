<p align="center">
  <h1 align="center">RapidxCloud Cryptography Core SDK</h1>
  <p align="center">
    <strong>Authoritative Pure-Rust Cryptographic Core & Cross-Platform SDK</strong><br>
    Zero-Knowledge Client-Side Encryption for Android (JNI), Web (WebAssembly), iOS, and Cloud Storage.
  </p>
</p>

<p align="center">
  <a href="https://github.com/aquib4040/rapidxcloud-crypto-sdk/actions/workflows/sdk-ci.yml"><img src="https://github.com/aquib4040/rapidxcloud-crypto-sdk/actions/workflows/sdk-ci.yml/badge.svg" alt="CI/CD Build & Test" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL%20v3-blue.svg" alt="License: GPL v3" /></a>
  <a href="https://rust-lang.org"><img src="https://img.shields.io/badge/Rust-2021%20Edition-orange.svg" alt="Rust Edition 2021" /></a>
  <a href="https://webassembly.org"><img src="https://img.shields.io/badge/WebAssembly-WASM32-purple.svg" alt="WASM" /></a>
  <a href="https://developer.android.com"><img src="https://img.shields.io/badge/Android-JNI%20%26%20NDK-green.svg" alt="Android JNI" /></a>
</p>

---

## Overview

`rapidxcloud-crypto-sdk` is the official, open-source, mathematically verifiable cryptographic engine powering [RapidxCloud](https://rapidxcloud.in) zero-knowledge cloud storage.

Built in 100% memory-safe Rust, it provides a single unified source of truth across all platforms—eliminating divergent implementations between native mobile apps, web browsers, and cloud microservices.

```text
                           ┌────────────────────────────────────────┐
                           │       RAPIDCLOUD CRYPTO CORE SDK       │
                           │              (crypto/core)             │
                           │ Pure Rust • Zeroize • Bounded Memory   │
                           └───────────────────┬────────────────────┘
                                               │
                     ┌─────────────────────────┴─────────────────────────┐
                     ▼                                                   ▼
      ┌─────────────────────────────┐                     ┌─────────────────────────────┐
      │      ANDROID / C-FFI        │                     │        BROWSER WASM         │
      │      (crypto/android)       │                     │        (crypto/wasm)        │
      │   canondrive_crypto (JNI)   │                     │   rapidxcloud_crypto.wasm   │
      └──────────────┬──────────────┘                     └──────────────┬──────────────┘
                     ▼                                                   ▼
           RapidXCloud Android App                                    web-new
           (AesChunkStreamer.kt)                           (aes.ts / wasm-crypto.ts)
```

---

## Core Security Properties

- **Zero-Knowledge Architecture:** Encryption and decryption occur exclusively inside the client's memory sandbox. The server never receives plaintext file contents, master keys, or sufficient information to reconstruct file keys.
- **Argon2id Password Key Derivation (RFC 9106):**
  - Interactive Profile: $m = 65536\text{ KiB}$ (64 MiB), $t = 3$ iterations, $p = 1$ parallelism.
  - Unicode NFC normalization enforced across all platforms before hashing.
  - Strict DoS boundary validation on all memory and iteration parameters.
- **AES-256-GCM Streaming AEAD (NIST SP 800-38D):**
  - 256-bit symmetric keys with fresh 96-bit CSPRNG nonces per chunk.
  - Self-describing chunk layout: `[ 12-byte IV ][ ciphertext ][ 16-byte Tag ]`.
  - Protocol V1 Associated Authenticated Data (AAD): `UTF-8("${chunk_index}|${total_chunks}")` binding preventing chunk reordering, dropped chunks, or inter-file splicing.
- **Dual-Key Splitting (Information-Theoretic One-Time Pad):**
  - Master file keys are split into independent shares: $\text{FileKey} = \text{ClientShare} \oplus \text{ServerShare}$.
  - The client share is sealed under the user's master key; the server share reveals zero bits of information without the user's secret.
- **Guaranteed Memory Zeroization:**
  - Sensitive buffers wrap `zeroize::ZeroizeOnDrop` (`SecureKey<N>`, `SecureBytes`), ensuring keys, nonces, and intermediate secrets are overwritten with zeros immediately upon leaving scope.
- **Mnemonic Recovery Key Envelope:**
  - 160-bit entropy Crockford Base32 recovery code.
  - Robust normalization translates lookalikes (`O/o -> 0`, `I/i/L/l -> 1`) and ignores spaces and hyphens.

---

## Workspace Crates

| Crate | Target | Description |
|:---|:---|:---|
| **`rapidxcloud-crypto-core`** (`core/`) | Pure Rust (`rlib`, `staticlib`) | Core cryptographic protocol primitives, key bags, streaming state machine, and test vectors. Free of platform-specific dependencies. |
| **`canondrive-crypto-android`** (`android/`) | Android Native (`cdylib`, `staticlib`) | Direct JNI bindings for Android Kotlin/Java apps (`NativeCrypto.kt`) and C-ABI Foreign Function Interface (FFI) for iOS and desktop. |
| **`rapidxcloud-crypto-wasm`** (`wasm/`) | WebAssembly (`cdylib`) | Pure C-ABI WebAssembly bridge for browser main threads, Web Worker pools, and Service Worker on-demand range streaming. |

---

## Building from Source

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (1.75+)
- WebAssembly target: `rustup target add wasm32-unknown-unknown`

### Running the Test Suite
```bash
# Run all pure Rust unit tests, envelope verification, and C-FFI safety tests
cargo test --workspace --verbose
```

### Compiling WebAssembly for Browser
```bash
cargo build -p rapidxcloud-crypto-wasm --target wasm32-unknown-unknown --release
```
The compiled output is located at:
`target/wasm32-unknown-unknown/release/rapidxcloud_crypto_wasm.wasm`

### Compiling for Android (NDK)
```bash
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release
```

---

## Automated Verification & Test Coverage

All cryptographic primitives are tested against RFC test vectors and adversarial edge cases:
- [x] RFC 9106 Argon2id derivation & Unicode NFC normalization parity
- [x] RFC 5869 HKDF-SHA256 multi-context domain separation
- [x] AES-256-GCM ciphertext, tag, nonce, and AAD tamper detection
- [x] Dual-Key XOR splitting and authenticated share sealing roundtrip
- [x] Out-of-order chunk replay & truncation rejection state machine
- [x] Crockford Base32 recovery code normalization with ambiguous character substitution
- [x] Memory zeroization on drop verification
- [x] C-FFI NULL pointer rejection and in-place XOR memory aliasing safety
- [x] Full bidirectional compatibility between legacy WebCrypto and Rust Core

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0) — see [LICENSE](LICENSE) for details.
