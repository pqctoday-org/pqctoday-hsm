# Systems Operations & Integration Guide

Welcome to the SoftHSMv3 Operations Guide. This document is for Systems
Administrators, DevOps Engineers, and SREs who want to **integrate and test**
the softhsmv3 PKCS#11 module (`libsofthsmv3.so` / `.dylib`) against third‑party
infrastructure such as OpenSSL, NGINX, strongSwan, OpenSSH, or Java (JCA/JCE)
applications.

> **Library name.** The PKCS#11 module is `libsofthsmv3` — `libsofthsmv3.so`
> on Linux, `libsofthsmv3.dylib` on macOS, `libsofthsmv3.wasm` for the browser
> build. (Do **not** use `libsofthsm2` or `libsofthsm3` — those names are
> wrong.) The default install path is
> `${libdir}/softhsm/libsofthsmv3${suffix}`.

> **Configuration file.** For SoftHSMv2 compatibility the loader still reads the
> `SOFTHSM2_CONF` environment variable. It points at a `softhsmv3.conf`
> (installed by default to `${sysconfdir}/softhsmv3.conf`). All processes that
> must share a token **must point `SOFTHSM2_CONF` at the same file** so they see
> the same `directories.tokendir`.

---

## 1. Storage Architecture — where tokens actually live

softhsmv3 has two distinct storage worlds. Pick the right mental model for the
build you are deploying.

### A. Native build — persistent by default

For a native (`.so` / `.dylib`) build the token store is **persistent to disk
by default**. Persistence is controlled by the `objectstore.backend` key in the
config file, not by any build flag:

| `objectstore.backend` | Backing store | Build requirement |
|---|---|---|
| `file` *(default)* | Flat‑file store under `directories.tokendir` (default `/var/lib/softhsmv3/tokens/`) | none — always available |
| `db` | Single SQLite3 database (transactional, better for high‑concurrency native IT) | build with `-DWITH_OBJECTSTORE_BACKEND_DB=ON` |

A minimal `softhsmv3.conf`:

```ini
directories.tokendir = /var/lib/softhsmv3/tokens
objectstore.backend  = file
log.level            = INFO
```

Because the native store is on disk, a token created with `softhsm2-util` /
`pkcs11-tool` **survives process exit**. NGINX, strongSwan, or Besu started
later — pointed at the same `SOFTHSM2_CONF` — will see the same keys. There is
no "vault dies on exit" problem for native deployments.

> There is **no `-DWITH_FILE_STORE=ON` flag** and **no `-DENABLE_MLKEM` /
> `-DENABLE_MLDSA` flags** — PQC is always compiled in with the OpenSSL backend.
> The only persistence‑related build flag is `-DWITH_OBJECTSTORE_BACKEND_DB=ON`,
> which *adds* the optional SQLite backend; the flat‑file backend is always
> built.

### B. WASM build — RAM‑only

The Emscripten/WASM build (`libsofthsmv3.wasm`, used for the in‑browser HSM)
runs against an in‑memory filesystem: there is **no host disk**, so token
material lives **exclusively in RAM** and is destroyed when the module is torn
down, unless the embedding page wires an IndexedDB (or equivalent) persistence
layer. The native `file` and `db` backends are compiled out of the WASM
pipeline to keep the JS bundle small. The RAM‑lifetime concerns below apply to
this build (and to any deliberately ephemeral native config), **not** to a
standard on‑disk native deployment.

### C. Stateful‑signature crash resilience (XMSS / LMS / HSS)

For hash‑based stateful signatures, the `CKA_HSS_KEYS_REMAINING` counter is
flushed to the object store immediately after each signature so the remaining
one‑time‑key count survives a crash and never reuses a state — provided you are
running a **persistent (native) backend**. Under the WASM/RAM model the counter
is only as durable as the embedding page's persistence layer, so never drive
production stateful signing from an ephemeral token.

---

## 2. Sharing one token across stateless processes (p11-kit)

For a **native, on‑disk** deployment you usually do **not** need a daemon: point
every process at the same `SOFTHSM2_CONF` and they all read the same on‑disk
token. Reach for `p11-kit` when you want a single mediated PKCS#11 endpoint —
for example to serve a WASM/RAM token to multiple clients, to centralise access
control, or to keep one long‑lived module instance.

### 2.1 Register the module with p11-kit

Create `/etc/pkcs11/modules/softhsmv3.module`:

```ini
module: /usr/local/lib/softhsm/libsofthsmv3.so
managed: no
```

### 2.2 Start a persistent p11-kit server

```bash
# Wrap in a systemd service for production use
p11-kit server --provider /usr/local/lib/softhsm/libsofthsmv3.so \
    --name "softhsmv3-daemon" \
    "pkcs11:"
```

### 2.3 Configure client processes

The `p11-kit server` prints a `P11_KIT_SERVER_ADDRESS` / `PKCS11_MODULE_PATH`
pointing at its UNIX socket. Inject it into NGINX, OpenVPN, or OpenSSL and those
applications talk to the shared module over IPC rather than loading their own
copy.

---

## 3. OpenSSL 3.x Provider Integration

SoftHSMv2 historically used `engine_pkcs11`, which is deprecated in OpenSSL
3.0+. softhsmv3 targets the modern **`pkcs11-provider`** architecture and
enforces **OpenSSL ≥ 3.5** at build time.

softhsmv3 vendors the [Latchset pkcs11-provider](https://github.com/latchset/pkcs11-provider)
under `src/vendor/pkcs11-provider/` (sources also mirrored at
`src/vendor/latchset/`) with ML‑KEM and ML‑DSA support already integrated.
Build it from the repo rather than pulling the upstream package.

### 3.1 Build and install the vendored provider

```bash
cd src/vendor/pkcs11-provider
meson setup build
ninja -C build
ninja -C build install
```

If OpenSSL is installed to a non‑system prefix, override the module directory:

```bash
meson setup build -Dopenssl_modulesdir=/opt/openssl-3.5/lib/ossl-modules
ninja -C build install
```

### 3.2 Update `openssl.cnf`

```ini
[provider_sect]
default = default_sect
pkcs11  = pkcs11_sect

[pkcs11_sect]
module = /usr/lib64/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/local/lib/softhsm/libsofthsmv3.so
```

### 3.3 Smoke test the provider

```bash
export SOFTHSM2_CONF=/etc/softhsmv3.conf
# The provider should load and list softhsmv3 as a PKCS#11 store:
openssl list -providers -provider pkcs11 -provider default
# Reference a key purely by URI (e.g. in NGINX):
#   ssl_certificate_key "pkcs11:token=ProdToken;object=MyPQCKey;type=private;";
```

---

## 4. StrongSwan IKEv2 Integration

The `strongswan-pkcs11/` adapter enables ML‑KEM‑768 key exchange and ML‑DSA
signing inside IKEv2 sessions.

### Prerequisites

* strongSwan built with `--enable-pkcs11`
* `libsofthsmv3.so` accessible to the strongSwan process
* A token initialized with keys pre‑generated, on a shared `SOFTHSM2_CONF`

### Configuration (`strongswan.conf`)

```ini
charon {
    plugins {
        pkcs11 {
            modules {
                softhsmv3 {
                    path = /usr/local/lib/softhsm/libsofthsmv3.so
                }
            }
        }
    }
}
```

### ML-KEM Key Exchange

The adapter's `pkcs11_kem_t` uses `C_EncapsulateKey` / `C_DecapsulateKey`
(PKCS#11 v3.2 §5.17) for the IKEv2 KE payload. The `token=` keyword in the
PKCS#11 URI selects which softhsmv3 token slot to use; the ML‑KEM mechanism is
resolved automatically when the peer negotiates a PQC key‑exchange group. All
three FIPS 203 sizes are registered — `ML-KEM-512`, `ML-KEM-768`, and
`ML-KEM-1024` — the variant used is whichever one the peers negotiate.

```ini
# swanctl.conf — pure PQC key exchange, no classical fallback
connections {
    peer {
        proposals = aes256-sha256-mlkem1024
        ...
    }
}
```

### Hybrid key exchange (RFC 9370)

The plugin rides strongSwan's own real, unmodified RFC 9370 multi-key-exchange
machinery (IKE_INTERMEDIATE, ADDKE1-7 transform types) — an ML-KEM group runs
as the standard IKE_SA_INIT key exchange while a classical ECP group is
negotiated as Additional Key Exchange 1 (`ke1_...`), so the resulting shared
secret combines both. This is not PQC-replaces-classical; both algorithms
contribute key material.

```ini
# swanctl.conf — hybrid: ML-KEM-1024 primary KE + ECP-256 as ADDKE1
connections {
    peer {
        proposals = aes256-sha256-mlkem1024-ke1_ecp256
        ...
    }
}
```

The same grammar works with `mlkem512` or `mlkem768` in place of `mlkem1024`
as the primary KE method. `strongswan-wasm-shims/wasm_backend.c` exercises
this exact proposal shape (`proposal_ike_hybrid`) in its hybrid proposal
mode, and `strongswan-pkcs11/README.md` documents the same examples for the
native plugin.

### ML-DSA Authentication

```bash
# Generate an ML-DSA-65 keypair inside softhsmv3
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsmv3.so \
    --keypairgen --key-type ML-DSA:65 \
    --id 01 --label "ike-mldsa-auth" --token-label "IKEv2Token"
```

```ini
# swanctl.conf
connections {
    peer {
        local {
            auth  = pubkey
            certs = "pkcs11:token=IKEv2Token;id=01;type=cert"
        }
    }
}
```

---

## 5. Java JCE Integration (Hyperledger Besu / JCA Apps)

The `JavaJCE/` module bridges standard JCA calls (`Signature`, `KeyAgreement`)
to softhsmv3 PKCS#11 v3.2, because the stock SunPKCS11 provider does not map
`"ML-DSA-65"` to `CKM_ML_DSA` (0x1d) on its own. See
`JavaJCE/JavaJCESofthsmv3.md` for the build and the exact provider class name.

### Deployment

```java
Security.addProvider(new org.softhsmv3.jce.SoftHSMJCEProvider());
```

After registration, `Signature.getInstance("ML-DSA-65")` and
`KeyAgreement.getInstance("ML-KEM-768")` route through `libsofthsmv3.so`.

### Key material for JCA

Keys generated via `pkcs11-tool` against the softhsmv3 token are visible to the
JCE layer:

```bash
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsmv3.so \
    --keypairgen --key-type ML-DSA:65 \
    --id 02 --label "besu-auth" --token-label "BesuToken"
```

---

## 6. KMIP server and other wrappers

softhsmv3 also ships a full **KMIP 3.0 / crypto‑agility server** and several
protocol wrappers. Their operational runbooks live with each component:

| Component | Runbook |
|---|---|
| KMIP server + client (build, TLS/mTLS, create/encrypt/locate, policies) | `kmip/README.md`, `kmip/python-client/README.md` |
| CACP compliance policy engine | `kmip/policies/README.md`, `kmip/cryptopolicy-manager/README.md` |
| OpenSSH over PKCS#11 | `openssh-pkcs11/README.md` |
| OpenPGP over PKCS#11 | `openpgp/README.md` (+ `openpgp/smoke-*/`) |
| MLS provider | `openmls-provider/README.md` |
| Rust engine (softhsmrustv3) conformance | `rust/README.md`, `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` |

---

## 7. Ephemeral‑token workarounds (WASM / RAM model only)

If you are deliberately running an ephemeral token (the WASM build, or a native
config fronted by a RAM‑lifetime daemon), keys are lost when the module tears
down. In that case bootstrap keys at start‑up:

1. Start the `p11-kit` server (or load the WASM module).
2. A bootstrap script uses `pkcs11-tool` against the endpoint to inject or
   generate keypairs.
3. Launch the dependent application (NGINX, Besu, strongSwan).

For any durable native deployment, prefer the on‑disk `file` or `db` backend in
§1.A instead — it removes the need for a bootstrapper entirely.
