cmake_minimum_required(VERSION 3.16)
project(softhsmv3 C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Build Options ----------------------------------------------------------

option(BUILD_TESTS "Compile tests along with libraries" OFF)
# Defaults to ON whenever tests are built: a failing test whose engine errors
# go only to syslog tells you nothing, which is exactly how the 2026-08 p11test
# flake stayed unexplained. Off for production builds.
option(LOG_TO_STDERR "Mirror engine log messages to stderr (default: on for test builds)" ${BUILD_TESTS})
option(DISABLE_NON_PAGED_MEMORY "Disable non-paged memory for secure storage" OFF)
option(DISABLE_VISIBILITY "Disables and unsets -fvisibility=hidden" OFF)
option(ENABLE_PEDANTIC "Enable pedantic compile mode" OFF)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(ENABLE_STATIC "Build static libraries" ON)
option(WITH_OBJECTSTORE_BACKEND_DB "Build with object store backend database (SQLite3)" OFF)

if(EMSCRIPTEN AND WITH_OBJECTSTORE_BACKEND_DB)
    set(WITH_OBJECTSTORE_BACKEND_DB OFF CACHE BOOL "Force disabled for WebAssembly backend" FORCE)
endif()

# ECC and EdDSA are always enabled — required for PQC roadmap.
# CompilerOptions.cmake tests ENABLE_ECC / ENABLE_EDDSA; WITH_ECC / WITH_EDDSA
# are set by CompilerOptions after the feature tests pass.
set(ENABLE_ECC ON)
set(ENABLE_EDDSA ON)

# ---- Version ----------------------------------------------------------------

set(VERSION "3.0.0")
set(VERSION_MAJOR 3)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(PACKAGE "softhsmv3")
set(PACKAGE_NAME "SoftHSMv3")
set(PACKAGE_VERSION "${VERSION}")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}")
set(PACKAGE_BUGREPORT "https://github.com/pqctoday-org/pqctoday-hsm/issues")
set(PACKAGE_URL "https://github.com/pqctoday-org/pqctoday-hsm")

# ---- Paths ------------------------------------------------------------------

if(NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
    set(CMAKE_INSTALL_SYSCONFDIR "/etc")
endif()
if(NOT DEFINED CMAKE_INSTALL_LOCALSTATEDIR)
    set(CMAKE_INSTALL_LOCALSTATEDIR "/var")
endif()
include(GNUInstallDirs)

set(DEFAULT_LOG_LEVEL "INFO"
    CACHE STRING "The default log level")
set(DEFAULT_OBJECTSTORE_BACKEND "file"
    CACHE STRING "Default storage backend for token objects")
set(DEFAULT_PKCS11_LIB "${CMAKE_INSTALL_FULL_LIBDIR}/softhsm/libsofthsmv3${CMAKE_SHARED_LIBRARY_SUFFIX}"
    CACHE STRING "The default PKCS#11 library")
set(DEFAULT_SOFTHSM2_CONF "${CMAKE_INSTALL_FULL_SYSCONFDIR}/softhsmv3.conf"
    CACHE STRING "The default location of softhsmv3.conf")
set(DEFAULT_TOKENDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/softhsmv3/tokens/"
    CACHE STRING "The default location of the token directory")
set(DEFAULT_UMASK "0077"
    CACHE STRING "The default file mode creation mask")

set(MAX_PIN_LEN 255 CACHE STRING "Maximum PIN length")
set(MIN_PIN_LEN 4 CACHE STRING "Minimum PIN length")

# ---- Build Type -------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build Configuration: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: C++${CMAKE_CXX_STANDARD}")

# ---- Crypto Backend: OpenSSL only -------------------------------------------

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_SOURCE_DIR}/cmake/modules)

# CompilerOptions.cmake drives crypto backend detection via WITH_CRYPTO_BACKEND.
# Phase 1: EVP-only API; OpenSSL >= 3.3 required (Ubuntu 24.04 ships 3.3).
# Phase 2 will re-raise to 3.5 when ML-DSA/ML-KEM EVP support is needed.
set(WITH_CRYPTO_BACKEND "openssl")

# ---- Compiler Options -------------------------------------------------------

include(CompilerOptions)
include(CompilerSanitizers)

# Enforce minimum OpenSSL version after CompilerOptions resolved the library.
if(OPENSSL_VERSION VERSION_LESS "3.5.0")
    message(FATAL_ERROR "OpenSSL >= 3.5.0 is required (found ${OPENSSL_VERSION})")
endif()
include(GenerateExportHeader)

# ---- Object Store -----------------------------------------------------------

if(WITH_OBJECTSTORE_BACKEND_DB)
    set(HAVE_OBJECTSTORE_BACKEND_DB 1)
    set(WITH_SQLITE3 ON)
    message(STATUS "Building with SQLite3 object store backend")
else()
    message(STATUS "Building with file object store backend")
endif()

# ---- Tests ------------------------------------------------------------------

enable_testing()

# ---- Config Header ----------------------------------------------------------

include_directories(${CMAKE_BINARY_DIR})

# ---- pkg-config .pc file (fixes OSS gap C2) ---------------------------------
# Generated into the build directory; installed to <libdir>/pkgconfig so that
# consumers can discover include paths and link flags via pkg-config.
configure_file(
    ${CMAKE_SOURCE_DIR}/softhsmv3.pc.in
    ${CMAKE_BINARY_DIR}/softhsmv3.pc
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/softhsmv3.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
        )

# ---- API Documentation (Doxygen, optional — fixes OSS gap M5) ---------------
find_package(Doxygen OPTIONAL_COMPONENTS dot)
if(DOXYGEN_FOUND)
    configure_file(
        ${CMAKE_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_BINARY_DIR}/Doxyfile
        @ONLY
    )
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating API documentation (output: ${CMAKE_BINARY_DIR}/docs/html/index.html)"
        VERBATIM
    )
    message(STATUS "Doxygen ${DOXYGEN_VERSION}: run 'cmake --build build --target docs' to generate API docs")
else()
    message(STATUS "Doxygen not found — 'cmake --build build --target docs' is unavailable")
endif()

# ---- Subdirectories ---------------------------------------------------------

if(EMSCRIPTEN)
    # WASM build: compile only the PKCS#11 library; skip utility binaries
    # (softhsm2-util, softhsm2-keyconv, softhsm2-dump require POSIX CLI)
    add_subdirectory(src/lib)
else()
    add_subdirectory(src)
endif()

if(NOT EMSCRIPTEN AND BUILD_TESTS)
    add_executable(p11_v32_compliance_test p11_v32_compliance_test.cpp)
    # OpenSSL is used as an INDEPENDENT reference oracle for KCV tests —
    # the test computes SHA-1(keyBits)[0:3] / AES-ECB(zero block)[0:3]
    # locally and compares against what the HSM returned. Without an
    # independent oracle the test can't tell a buggy KCV from a buggy
    # SHA-1 digest in the HSM that happens to fail in the same direction.
    target_include_directories(p11_v32_compliance_test PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(p11_v32_compliance_test dl ${OPENSSL_LIBRARIES})

    # Run the PKCS#11 v3.2 compliance suite under ctest against the freshly
    # built engine. Hermetic: token store + softhsm2.conf + reports all live
    # in the build directory (no /tmp or source-tree pollution). The binary
    # exits non-zero only on unexpected FAILs (documented XFAILs do not fail
    # the test; they are reported in cpp_compliance_report.{md,json}).
    add_test(NAME p11_v32_compliance
             COMMAND p11_v32_compliance_test
                     --engine $<TARGET_FILE:softhsmv3>
                     --workdir ${CMAKE_BINARY_DIR}/p11_v32_compliance_workdir
                     --report ${CMAKE_BINARY_DIR}/cpp_compliance_report
             WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

    # composite-sig-probe: phase-4 R7 test helper for the pkcs11-provider's
    # composite (draft-lamps-pq-composite-sigs) signature support. Links
    # pkcs11-provider.so directly (its composite bridge exports real C
    # symbols for exactly this — see composite.h) because the standard
    # openssl CLI cannot reach that path: there is no keymgmt GEN for
    # composite keys, only a two-subkey-URI bridge. Driven by
    # scripts/test-openssl-provider.sh's T21 (COMPSIG) cases, not run
    # under ctest directly (it needs a live per-case token arena the
    # harness script builds, same as every other T-case).
    add_executable(composite_sig_probe scripts/composite-sig-probe.c)
    target_include_directories(composite_sig_probe PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/src/vendor/pkcs11-provider
        ${CMAKE_SOURCE_DIR}/src/vendor/pkcs11-provider/src)
    add_dependencies(composite_sig_probe pkcs11-provider)
    # pkcs11-provider is a MODULE library named exactly pkcs11-provider.so
    # (no "lib" prefix, per provider-loading convention). CMake recognizes
    # any reference to its output path — target name, $<TARGET_FILE:...>,
    # even a hardcoded literal matching that path — as "the pkcs11-provider
    # target" and re-derives a bare -lpkcs11-provider flag, which the
    # linker can't resolve (it looks for libpkcs11-provider.so). The GNU
    # ld/gold/lld -l:exact-filename form bypasses the lib-prefix
    # assumption while staying inside target_link_libraries' normal
    # library ordering (so it lands after the object file that needs its
    # symbols, unlike target_link_options' flag placement).
    target_link_libraries(composite_sig_probe
        ${OPENSSL_LIBRARIES}
        -L${CMAKE_BINARY_DIR}/src/vendor/pkcs11-provider
        -l:pkcs11-provider.so
        -Wl,-rpath,${CMAKE_BINARY_DIR}/src/vendor/pkcs11-provider)

    # dump-int-param: phase-4 R20 (F36-5) test helper — reads back an
    # arbitrary EVP_PKEY int param (OSSL_PKEY_PARAM_SECURITY_CATEGORY)
    # via the standard EVP API. Unlike composite_sig_probe this needs no
    # pkcs11-provider.so internal symbols — the provider is loaded at
    # runtime via openssl.cnf like any normal application, so plain
    # OpenSSL linking is enough.
    add_executable(dump_int_param scripts/dump-int-param.c)
    target_include_directories(dump_int_param PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(dump_int_param ${OPENSSL_LIBRARIES})

    # lms-xdr-verify: phase-4 R9 test helper. Verifies an HSS-token-signed
    # signature using OpenSSL 3.6.3's own native LMS implementation,
    # independent of the pkcs11-provider and the engine — see the file's
    # own header comment for why the openssl CLI can't reach this path
    # (the "xdr" LMS decoder has no PEM/DER auto-detect entry) and why two
    # HSS-vs-bare-LMS wire-format strips are needed first. Driven by T24.
    add_executable(lms_xdr_verify scripts/lms-xdr-verify.c)
    target_include_directories(lms_xdr_verify PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(lms_xdr_verify ${OPENSSL_LIBRARIES})

    # hss-pubkey-dump: phase-4 R9 test helper — raw CKA_VALUE export for a
    # token's HSS public key via direct PKCS#11 calls (no SPKI encoder
    # exists for HSS in the pkcs11-provider; see the file's own header).
    add_executable(hss_pubkey_dump scripts/hss-pubkey-dump.c)
    target_include_directories(hss_pubkey_dump PRIVATE
        ${CMAKE_SOURCE_DIR}/src/lib/pkcs11)
    target_link_libraries(hss_pubkey_dump ${CMAKE_DL_LIBS})

    # hss-w4-keygen: phase-5 R25 test helper — generates an HSS keypair
    # with explicit non-default CK_HSS_KEY_PAIR_GEN_PARAMS (LMOTS W4) via
    # direct PKCS#11 calls, proving sig/hss.c's hss_sig_size() computes a
    # genuinely different, per-parameter-set signature length rather than
    # a constant that happens to be right once (see the file's own
    # header). Driven by T24c.
    add_executable(hss_w4_keygen scripts/hss-w4-keygen.c)
    target_include_directories(hss_w4_keygen PRIVATE
        ${CMAKE_SOURCE_DIR}/src/lib/pkcs11)
    target_link_libraries(hss_w4_keygen ${CMAKE_DL_LIBS})

    # hss-fallback-fixture: phase-6 R29 test helper — creates a public
    # HSS key object via direct C_CreateObject holding a real CKA_VALUE
    # but WITHOUT the official CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE attrs,
    # simulating a pre-R25-engine or imported key so hss_sig_size_for_
    # key()'s own CKA_VALUE-parsing fallback leg (never live-tested when
    # R25 landed, for want of a fixture) can finally be proven (see the
    # file's own header for why it's built from a W4, not W8, key).
    add_executable(hss_fallback_fixture scripts/hss-fallback-fixture.c)
    target_include_directories(hss_fallback_fixture PRIVATE
        ${CMAKE_SOURCE_DIR}/src/lib/pkcs11)
    target_link_libraries(hss_fallback_fixture ${CMAKE_DL_LIBS})

    # aead-probe: phase-5 R26 test helper — exercises the full EVP AEAD
    # workflow (AAD, tag get/set, both sabotage controls) for
    # CKM_AES_GCM / CKM_CHACHA20_POLY1305, since `openssl enc` refuses
    # AEAD ciphers outright (see the file's own header).
    add_executable(aead_probe scripts/aead-probe.c)
    target_include_directories(aead_probe PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(aead_probe ${OPENSSL_LIBRARIES})

    # aead-edge-probe: phase-6 R30 test helper — over-ceiling decrypt
    # (must fail cleanly, never crash/corrupt) and AAD-only/empty-
    # plaintext AEAD decrypt, purpose-built rather than folded into
    # aead-probe.c's own happy-path+sabotage shape (see the file's own
    # header).
    add_executable(aead_edge_probe scripts/aead-edge-probe.c)
    target_include_directories(aead_edge_probe PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(aead_edge_probe ${OPENSSL_LIBRARIES})

    # skey-flow-probe: phase-5 R24 (F36-3) test helper — exercises the
    # EVP_SKEY opaque-key API (generate/derive_SKEY/init_SKEY) against
    # this provider's SKEYMGMT/HKDF/HMAC, cross-checking the derived
    # key's correctness against independent software computation without
    # ever exporting the intermediate key material. Plain OpenSSL linking
    # (loads pkcs11-provider at runtime like any application), no
    # provider-internal symbols needed.
    add_executable(skey_flow_probe scripts/skey-flow-probe.c)
    target_include_directories(skey_flow_probe PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(skey_flow_probe ${OPENSSL_LIBRARIES})
endif()
