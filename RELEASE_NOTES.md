## RapidxCloud Cryptography Core SDK v2.0.0

Official initial release of the RapidxCloud pure-Rust cryptographic engine and cross-platform SDK.

### What is Included
- **WebAssembly Engine (`rapidxcloud_crypto_wasm.wasm`):** Standalone zero-knowledge WebAssembly core for browser main thread, Web Workers, and Service Worker range-streaming.
- **Native JNI & C-FFI Engine (`librapidxcloud_crypto.so`):** Native shared library for Android and Linux.

### Key Security & Cryptographic Features
- **Argon2id Key Derivation (RFC 9106):** 64 MiB interactive profile with Unicode NFC normalization.
- **AES-256-GCM Streaming AEAD:** 4 MiB chunks with `$index|$total` AAD position binding.
- **Information-Theoretic Key Splitting:** `FileKey = ClientShare ⊕ ServerShare`.
- **Crockford Base32 Recovery Keys:** 160-bit entropy with ambiguous character substitution.
- **Guaranteed Zeroization:** `SecureKey<N>` and `SecureBytes` with `ZeroizeOnDrop`.
- **Protocol V1 Backward Compatibility:** 100% compatible with existing accounts and encrypted files.

### Binary Verification Hashes (SHA-256)
- `rapidxcloud_crypto_wasm.wasm`: `03645abcf5c78a4fc799a1748537df6e5028cd41d1ccd287996ed044a5862b7c`
- `librapidxcloud_crypto.so`: `a3c51c0fe8df60c339309515dfb5daec27456917577099c541f581af9ccd5f78`

