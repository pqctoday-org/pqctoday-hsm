> **SUPERSEDED.** This is the original, single-commit early design doc for
> `softhsmrustv3` — it predates the engine that actually shipped and
> describes concepts (a `HashMap<u32, Vec<u8>>` in-memory object store,
> generic direct use of the `ml-kem`/`ml-dsa`/`slh-dsa` crates, no mention
> of a native C-ABI, KMIP, HPKE, or conformance evidence) that the real
> engine has long since grown past. Kept for historical/context value only
> — **do not cite anything in this file as describing the current engine.**
> For the current state, see [`rust/README.md`](rust/README.md) (build,
> testing, conformance — 999/0 PKCS#11 v3.2 conformance checks as of this
> note) and [`docs/rust-engine.md`](docs/rust-engine.md) (architecture,
> technology stack, current status).

# SoftHSMv3 Rust WebAssembly Port (softhsmrustv3)

## 1. Executive Summary

This document describes the architectural design for the WebAssembly port of SoftHSMv3.
The existing C++ `SoftHSMv3` implementation relies heavily on OpenSSL 3.6 to provide its cryptographic backend. While C++ and OpenSSL can technically be compiled to WebAssembly via Emscripten (`emcc`), this approach introduces significant drawbacks: massive bundle sizes, complicated single-threaded memory models, complex build toolchains, and severe limitations when running directly in browser environments.

To achieve maximum efficiency, `softhsmrustv3` is written entirely in "Pure Rust" and compiled natively to the bare-metal `wasm32-unknown-unknown` target. It completely replaces the OpenSSL backend with native Rust cryptographic implementations while aggressively maintaining 100% ABI/API parity with the Emscripten output.

---

## 2. API Parity & Integration Strategy

### The "Disguise" Technique

The core requirement is that existing JavaScript consumers (like the web app or Node.js test suites) that were originally written against the C++ Emscripten build MUST continue working without changing a single line of JavaScript code.

Emscripten exposes C functions by prefixing them with an underscore (e.g., `_C_Initialize`, `_C_GenerateKeyPair`) and provides memory management functions (`_malloc`, `_free`).

To achieve drop-in parity without Emscripten, the Rust WASM module uses `wasm-bindgen` and explicitly forces the exported JavaScript names to match the C++ Emscripten signatures verbatim:

```rust
#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    _hSession: u32,
    _pMechanism: *mut u8,
    // ...
) -> u32 {
    // ... native Rust implementation ...
}
```

The consumer executes `_C_GenerateKeyPair` believing it is talking to the Emscripten C++ boundary, when in reality it is directly invoking the native Rust WASM memory router.

---

## 3. Cryptography Backend Design

To successfully compile to `wasm32-unknown-unknown` avoiding all C-Dependencies, `softhsmrustv3` leverages the **RustCrypto** organization libraries.

### 3.1 Post-Quantum Cryptography (PQC)

We rely entirely on pure-Rust algorithms, eliminating the need for C-based wrappers like `liboqs` or `PQClean`.

* **`ml-kem` crate:** Implements NIST FIPS 203 (Key Encapsulation Mechanism). Used directly by `C_GenerateKeyPair`, `C_EncapsulateKey`, and `C_DecapsulateKey`.
* **`ml-dsa` crate:** Implements NIST FIPS 204 (Digital Signatures).
* **`slh-dsa` crate:** Implements NIST FIPS 205 (Hash-based Signatures).

*Dependency Resolution Note:* Building the PQC suite requires specific version locking (e.g., `ml-dsa = "=0.1.0-rc.7"` and `slh-dsa = "=0.2.0-rc.4"`) to ensure the underlying `signature` trait architectures do not conflict within Cargo.

### 3.2 Classical Cryptography (AES, SHA)

To maintain purity, OpenSSL is eradicated entirely. The classical primitives are supported by:

* **`aes` / `ctr` / `aes-gcm` crates:** Native block cipher modes mimicking `C_Encrypt` / `C_Decrypt`.
* **`sha2` / `sha3` / `hmac` crates:** Native hashing and message authentication.

### 3.3 The Execution Flow (Example)

When the frontend asks to generate a Post-Quantum Key:

1. **Javascript Call:** Calls `M._C_GenerateKeyPair(...)` requesting `CKM_ML_KEM`.
2. **Rust Router:** The bounded Rust function `_C_GenerateKeyPair` receives the request.
3. **WASM Computation:** Rust executes `ml_kem::MlKem768::generate(...)` internally. The complex crystal-lattice math happens natively within the WASM engine.
4. **Hardware Simulation:** The generated raw bytes are pushed into a static, secure `HashMap<u32, Vec<u8>>` sitting in the linear Rust memory, completely isolated from JS scope.
5. **Return Handles:** Rust returns arbitrary integer "handles" (e.g., `Object ID 2`) back to the JS caller.
6. **Subsequent Use:** When JS calls `_C_EncapsulateKey(2)`, Rust safely retrieves the key from its internal HashMap and invokes `.encapsulate()` securely.

---

## 4. Build Toolchain Advantages

By removing C++ and OpenSSL:

1. **No `emcc` or CMake:** We no longer require the heavy Emscripten toolchain in the development environment.
2. **Native compilation:** Run `cargo build --target wasm32-unknown-unknown` and it emits a clean `.wasm` file instantly.
3. **WASM Opt Exception:** Because the pure Rust PQC libraries leverage bulk memory operations (like `memory.copy` and `memory.fill`), we explicitely define `wasm-opt = false` inside `Cargo.toml`. `wasm-pack`'s default optimizer does not support bulk-memory instructions currently, but raw V8 (Node/Chrome) runs it flawlessly.
4. **Shim Wrapper:** We utilize a tiny 20-line Javascript wrapper (`softhsm.js`) to mimic the Emscripten factory constructor (`createSoftHSMModule`), seamlessly funneling all WebAssembly raw memory buffers the exact way the C++ module did.

## Summary

`softhsmrustv3` guarantees:

* **100% Pure Rust Cryptography**
* **Drop-in PKCS#11 C API compatibility**
* **Native WebAssembly performance with zero C-FFI overhead**
