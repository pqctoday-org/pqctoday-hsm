project(pkcs11-provider C)

find_package(OpenSSL REQUIRED)

add_definitions(-Wno-unused-parameter -fno-strict-aliasing)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})

# src/config.h (included unconditionally by src/provider.h) is meson's job
# upstream (configure_file() at the bottom of the vendored meson.build) and
# is .gitignore'd here. Two problems that created (audit WART-3,
# docs/openssl-provider-coverage-audit-2026-08-25.md):
#   1. Nothing in the NATIVE build path ever generated it — a truly fresh
#      checkout that never ran the WASM build (scripts/build-pkcs11-provider-
#      wasm.sh, the only caller of scripts/gen-pkcs11-provider-config-h.sh)
#      would fail outright with "config.h: file not found" the moment
#      provider.h's #include ran. Every native build that "worked" here did
#      so only because a stale WASM-generated config.h happened to already
#      sit in this directory from unrelated tooling.
#   2. When that stale file WAS present, its macros (PACKAGE_MAJOR,
#      P11PROV_VERSION, ...) collided with this file's own
#      add_definitions(-D...) of the same names — "PACKAGE_* redefined"
#      warnings, and #include wins over -D (it's processed later), so the
#      live provider reported the WASM build's version (1.1) instead of
#      this build's own.
# Fix: generate a real config.h here too, unconditionally, every configure
# — single source of truth is the vendored meson.build's own `version:`
# field (same field scripts/gen-pkcs11-provider-config-h.sh parses for the
# WASM build), so both build paths report the SAME provider version instead
# of two disagreeing hardcoded numbers. This also means a native (re)configure
# always overwrites any stale WASM leftover with a correct, current file.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/meson.build" P11PROV_VERSION_LINE
     REGEX "^  version: '")
string(REGEX MATCH "'([^']+)'" _ "${P11PROV_VERSION_LINE}")
set(P11PROV_VERSION "${CMAKE_MATCH_1}")
if(NOT P11PROV_VERSION)
  message(FATAL_ERROR "pkcs11-provider: could not parse version: from meson.build")
endif()
string(REPLACE "." ";" P11PROV_VERSION_PARTS "${P11PROV_VERSION}")
list(GET P11PROV_VERSION_PARTS 0 P11PROV_VERSION_MAJOR)
list(GET P11PROV_VERSION_PARTS 1 P11PROV_VERSION_MINOR)
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h"
"/* GENERATED at CMake configure time (src/vendor/pkcs11-provider/CMakeLists.txt)
 * for the native build — do not edit; do not commit (see .gitignore). Mirrors
 * the macros the vendored meson.build's own configure_file(output: 'config.h')
 * would produce for a meson build, and scripts/gen-pkcs11-provider-config-h.sh
 * produces for the WASM build — all three derive P11PROV_VERSION from the same
 * meson.build `version:` field, so it cannot silently disagree across build
 * paths the way the previous hardcoded native \"0.4.0\" did against the real
 * 1.1 the other two paths report. */
#pragma once

#define PACKAGE_NAME \"pkcs11-provider\"
#define PACKAGE_MAJOR ${P11PROV_VERSION_MAJOR}
#define PACKAGE_MINOR ${P11PROV_VERSION_MINOR}

#define P11PROV_VERSION \"${P11PROV_VERSION}\"
#define P11PROV_BUILDINFO \"${P11PROV_VERSION}-cmake\"

#define HAVE_DLFCN_H 1
")

set(PROVIDER_SOURCES
    src/asymmetric_cipher.c
    src/chacha.c
    src/cipher.c
    src/composite.c
    src/debug.c
    src/decoder.c
    src/digests.c
    src/encoder.c
    src/exchange.c
    src/kdf.c
    src/keymgmt.c
    src/mac.c
    src/pk11_uri.c
    src/interface.c
    src/objects.c
    src/provider.c
    src/random.c
    src/session.c
    src/sig/signature.c
    src/sig/rsasig.c
    src/sig/ecdsa.c
    src/sig/eddsa.c
    src/sig/mldsa.c
    src/skeymgmt.c
    src/slot.c
    src/store.c
    src/tls.c
    src/util.c
    src/kem/mlkem.c
    src/sig/slhdsa.c
    src/sig/xmss.c
    src/sig/hss.c
)

add_library(pkcs11-provider MODULE ${PROVIDER_SOURCES})
set_target_properties(pkcs11-provider PROPERTIES PREFIX "")
target_link_libraries(pkcs11-provider ${OPENSSL_LIBRARIES})
