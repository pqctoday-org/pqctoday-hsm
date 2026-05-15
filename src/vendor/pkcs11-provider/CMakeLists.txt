project(pkcs11-provider C)

find_package(OpenSSL REQUIRED)

add_definitions(-Wno-unused-parameter -fno-strict-aliasing)
add_definitions(-DP11PROV_VERSION="0.4.0" -DP11PROV_BUILDINFO="0.4.0-cmake" -DPACKAGE_MAJOR=0 -DPACKAGE_MINOR=4 -DPACKAGE_NAME="pkcs11-provider")

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})

set(PROVIDER_SOURCES
    src/asymmetric_cipher.c
    src/cipher.c
    src/composite.c
    src/debug.c
    src/decoder.c
    src/digests.c
    src/encoder.c
    src/exchange.c
    src/kdf.c
    src/keymgmt.c
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
)

add_library(pkcs11-provider MODULE ${PROVIDER_SOURCES})
set_target_properties(pkcs11-provider PROPERTIES PREFIX "")
target_link_libraries(pkcs11-provider ${OPENSSL_LIBRARIES})
