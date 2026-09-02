## Build & Installation

> **SoftHSMv3 fork note:** this file documents the upstream Latchset
> `meson`/`ninja` build, unmodified. This fork adds a **second**, parallel
> build for this same provider — `src/vendor/pkcs11-provider/CMakeLists.txt`
> — wired unconditionally into the repo root's own build
> (`src/CMakeLists.txt` → `add_subdirectory(vendor/pkcs11-provider)`). If
> you already ran this repo's normal native build (root `README.md`'s
> "Building" section — `cmake -B build ... && cmake --build build`), you
> already have a complete provider at
> `build/src/vendor/pkcs11-provider/pkcs11-provider.so`; you do not need to
> run the steps below at all for local development against this repo's own
> engines. `scripts/test-openssl-provider.sh` and
> `scripts/local-gate.sh --openssl-provider` use that CMake-built artifact
> by default, not this meson build.
>
> **Known gap (check before relying on this build path):** as of this
> writing, `src/meson.build`'s `pkcs11_provider_sources` list does not
> include `mac.c`, `chacha.c`, or `sig/hss.c` — three files this fork added
> for EVP_MAC (HMAC/CMAC/KMAC), ChaCha20/ChaCha20-Poly1305, and HSS/LMS
> signature support, respectively (`src/vendor/pkcs11-provider/CMakeLists.txt`'s
> `PROVIDER_SOURCES` already lists all three correctly). A provider built
> via the steps below will compile and link (the OpenSSL provider is a
> loadable module, so missing symbols aren't always caught until load time)
> but currently fails to load — `openssl list -providers -provider pkcs11`
> reports an undefined-symbol error the first time OpenSSL tries to use it.
> Use the standalone meson build only if you need a provider installed
> system-wide independent of this repo's build tree, and check
> `src/meson.build`'s source list for `mac.c`/`chacha.c`/`sig/hss.c` first.

### Prerequisites

This package requires the following:
- OpenSSL 3.0.7+ libraries and development headers
- OpenSSL tools (for testing)
- NSS softoken, tools and development headers (for testing)
- a C compiler that supports at least C11 semantics
- meson
- pkg-config
- p11-kit, p11-kit-devel, opensc and softhsm (for testing)
- Kryoptic softoken (for testing)

### Build

The usual command to build are:
- `meson setup builddir`
- `meson compile -C builddir`
- `meson test -C builddir`

To link with OpenSSL installed in a custom path, set
`PKG_CONFIG_PATH`, or `CFLAGS`/`LDFLAGS` envvars accordingly at the
`meson setup` step. For example, let's assume OpenSSL is installed
under an absolute path `$OPENSSL_DIR`.

If you rely on pkg-config, point `PKG_CONFIG_PATH` to a directory
where `libcrypto.pc` or `openssl.pc` can be found.

- `PKG_CONFIG_PATH="$OPENSSL_DIR/lib64/pkgconfig" meson setup builddir`

Otherwise, you can set `CFLAGS`/`LDFLAGS`:

- `CFLAGS="-I$OPENSSL_DIR/include" LDFLAGS="-L$OPENSSL_DIR/lib64" meson setup builddir`

A "build info" string (which can be seen via openssl list -providers -verbose) can be set
by using the build_info option before compilation:
- `meson configure -Dbuild_info="Build-Id: 123456789" builddir

### Installation

The usual command to install is:

- `meson install -C builddir`

Or simply copy the `src/pkcs11.so` (or `src/pkcs11.dylib` on Mac) in the appropriate directory for your OpenSSL installation.
