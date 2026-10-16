# OpenSSL Studio link inputs

Source files that `scripts/build-openssl-studio-wasm.sh` links into the
`openssl-pkcs11` engine bundle (`openssl.js` + `openssl.wasm`, declared in
`engines/bundles.json`). They moved here from the PQC Today Hub
(`src/wasm/`), which serves the bundle, so the bundle is built and published
from this repository like the other engines.

| File | Origin | Licence |
|---|---|---|
| `shims/tls_simulation.c` | PQC Today Hub, `src/wasm/` | AGPL-3.0-only |
| `shims/tls_simulation_hsm.c` | PQC Today Hub, `src/wasm/` | AGPL-3.0-only |
| `shims/pkcs11_static_shim.c` | PQC Today Hub, `src/wasm/` | AGPL-3.0-only |
| `shims/cms_provider_init.c` | PQC Today Hub, `src/wasm/` | AGPL-3.0-only |
| `shims/cmp_simulation.c` | PQC Today Hub, `src/wasm/` | AGPL-3.0-only |
| `patches/0001-apps_startup-register-pkcs11-provider.patch` | PQC Today, a change to OpenSSL 3.6.3 `apps/openssl.c` | Apache-2.0, the licence of the OpenSSL file it changes |

The shims are original work, Copyright (c) 2026 PQC Today, LLC. Each carries
an `SPDX-License-Identifier` line; the full text of the GNU Affero General
Public License version 3 is in `LICENSES/AGPL-3.0-only.txt`. They match the
Hub's copies apart from the SPDX line (the Hub moves to AGPL-3.0-only too).
Versions published before 16 October 2026 were GPL-3.0-only.

What each shim does:

- `tls_simulation.c`: an in-process TLS 1.3 client and server joined by
  memory BIOs (`execute_tls_simulation`).
- `tls_simulation_hsm.c`: the HSM mode of the same simulator; the server key
  lives in the PKCS#11 token and signing goes through pkcs11-provider.
- `pkcs11_static_shim.c`: replaces `dlopen`/`dlsym` so pkcs11-provider binds
  to the statically linked PKCS#11 engine.
- `cms_provider_init.c`: registers pkcs11-provider for the CLI and exposes
  the LAMPS composite certificate and CMS helpers.
- `cmp_simulation.c`: an in-process CMP client and server that really issues
  the requested certificate.

The patch makes every `openssl` command register pkcs11-provider at start-up,
because the module is built with `-sEXIT_RUNTIME=1` and each `callMain()`
starts a fresh runtime.
