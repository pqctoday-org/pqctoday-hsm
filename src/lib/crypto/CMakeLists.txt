project(softhsm_crypto)

# OpenSSL-only backend. Botan, DES, DSA, DH, GOST have been removed.
# MD5 (digest/HMAC/RSA-PKCS#1v1.5 sign) is retained for non-FIPS interop --
# see the OSSLCryptoFactory.cpp header comment.
# ECC and EdDSA are always enabled.

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES
    # Abstract base classes (retained algorithms)
    AESKey.cpp
    AsymmetricAlgorithm.cpp
    AsymmetricKeyPair.cpp
    CryptoFactory.cpp
    DerUtil.cpp
    ECParameters.cpp
    ECPrivateKey.cpp
    ECPublicKey.cpp
    EDPrivateKey.cpp
    EDPublicKey.cpp
    HashAlgorithm.cpp
    MacAlgorithm.cpp
    RSAParameters.cpp
    RSAPrivateKey.cpp
    RSAPublicKey.cpp
    SymmetricAlgorithm.cpp
    SymmetricKey.cpp
    HDWalletDerivation.cpp

    # ML-DSA (FIPS 204) abstract bases and parameters
    MLDSAPublicKey.cpp
    MLDSAPrivateKey.cpp
    MLDSAParameters.cpp

    # SLH-DSA (FIPS 205) abstract bases and parameters
    SLHDSAPublicKey.cpp
    SLHDSAPrivateKey.cpp
    SLHDSAParameters.cpp

    # ML-KEM (FIPS 203) abstract bases and parameters
    MLKEMPublicKey.cpp
    MLKEMPrivateKey.cpp
    MLKEMParameters.cpp

    # OpenSSL EVP implementations
    OSSLAES.cpp
    OSSLCMAC.cpp
    OSSLComp.cpp
    OSSLCryptoFactory.cpp
    OSSLChaCha20.cpp
    OSSLECDH.cpp
    OSSLECDSA.cpp
    OSSLECKeyPair.cpp
    OSSLECPrivateKey.cpp
    OSSLECPublicKey.cpp
    OSSLEDDSA.cpp
    OSSLEDKeyPair.cpp
    OSSLEDPrivateKey.cpp
    OSSLEDPublicKey.cpp
    OSSLMLDSA.cpp
    OSSLMLDSAKeyPair.cpp
    OSSLMLDSAPrivateKey.cpp
    OSSLMLDSAPublicKey.cpp
    OSSLSLHDSA.cpp
    OSSLSLHDSAKeyPair.cpp
    OSSLSLHDSAPrivateKey.cpp
    OSSLSLHDSAPublicKey.cpp
    OSSLMLKEM.cpp
    OSSLMLKEMKeyPair.cpp
    OSSLMLKEMPrivateKey.cpp
    OSSLMLKEMPublicKey.cpp
    OSSLEVPCMacAlgorithm.cpp
    OSSLEVPHashAlgorithm.cpp
    OSSLEVPMacAlgorithm.cpp
    OSSLEVPSymmetricAlgorithm.cpp
    OSSLHMAC.cpp
    OSSLKMAC.cpp
    OSSLGMAC.cpp
    OSSLMD5.cpp
    OSSLRNG.cpp
    OSSLRSA.cpp
    OSSLRSAKeyPair.cpp
    OSSLRSAPrivateKey.cpp
    OSSLRSAPublicKey.cpp
    OSSLRIPEMD160.cpp
    OSSLSHA1.cpp
    OSSLSHA224.cpp
    OSSLSHA256.cpp
    OSSLSHA384.cpp
    OSSLSHA512.cpp
    OSSLSHA3.cpp
    OSSLUtil.cpp

    # Stateful Stateful Signatures (LMS/HSS and XMSS)
    stateful/hash-sigs/endian.c
    stateful/hash-sigs/hash.c
    stateful/hash-sigs/hss.c
    stateful/hash-sigs/hss_alloc.c
    stateful/hash-sigs/hss_aux.c
    stateful/hash-sigs/hss_common.c
    stateful/hash-sigs/hss_compute.c
    stateful/hash-sigs/hss_derive.c
    stateful/hash-sigs/hss_generate.c
    stateful/hash-sigs/hss_keygen.c
    stateful/hash-sigs/hss_param.c
    stateful/hash-sigs/hss_reserve.c
    stateful/hash-sigs/hss_sign.c
    stateful/hash-sigs/hss_sign_inc.c
    $<IF:$<BOOL:${EMSCRIPTEN}>,stateful/hash-sigs/hss_thread_single.c,stateful/hash-sigs/hss_thread_pthread.c>
    stateful/hash-sigs/hss_verify.c
    stateful/hash-sigs/hss_verify_inc.c
    stateful/hash-sigs/hss_zeroize.c
    stateful/hash-sigs/lm_common.c
    stateful/hash-sigs/lm_ots_common.c
    stateful/hash-sigs/lm_ots_sign.c
    stateful/hash-sigs/lm_ots_verify.c
    stateful/hash-sigs/lm_verify.c
    stateful/xmss-reference/fips202.c
    stateful/xmss-reference/hash.c
    stateful/xmss-reference/hash_address.c
    stateful/xmss-reference/params.c
    stateful/kat_randombytes.c
    stateful/xmss-reference/utils.c
    stateful/xmss-reference/wots.c
    stateful/xmss-reference/xmss.c
    stateful/xmss-reference/xmss_commons.c
    stateful/xmss-reference/xmss_core_fast.c
    )

include_directories(${INCLUDE_DIRS} stateful/hash-sigs stateful/xmss-reference)

include_directories(${INCLUDE_DIRS})
add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

if(NOT CMAKE_VERSION VERSION_LESS "3.12")
    target_link_libraries(${PROJECT_NAME} ${CRYPTO_LIBS})
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
