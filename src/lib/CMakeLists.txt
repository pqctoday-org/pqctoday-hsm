###############################################################################
# Dependencies
###############################################################################
add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(data_mgr)
add_subdirectory(handle_mgr)
add_subdirectory(object_store)
add_subdirectory(session_mgr)
add_subdirectory(slot_mgr)

###############################################################################
# SoftHSMv2 Config
###############################################################################
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/common
                 ${CMAKE_CURRENT_SOURCE_DIR}/crypto
                 ${CMAKE_CURRENT_SOURCE_DIR}/data_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/handle_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/object_store
                 ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11
                 ${CMAKE_CURRENT_SOURCE_DIR}/session_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/slot_mgr
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES access.cpp
            main.cpp
            P11Attributes.cpp
            P11Objects.cpp
            SoftHSM.cpp
            SoftHSM_digest.cpp
            SoftHSM_kem.cpp
            SoftHSM_sessions.cpp
            SoftHSM_slots.cpp
            SoftHSM_objects.cpp
            SoftHSM_cipher.cpp
            SoftHSM_sign.cpp
            SoftHSM_keygen.cpp
            )

set(STATIC_FILES softhsm_common
                 softhsm_crypto
                 softhsm_datamgr
                 softhsm_handlemgr
                 softhsm_objectstore
                 softhsm_sessionmgr
                 softhsm_slotmgr
                 )

if(CMAKE_VERSION VERSION_LESS "3.12")
        # Older CMake versions cannot link object libraries to a target, so pass
        # the associated object files as source. Similarly, softhsm_crypto and
        # softhsm_objectstore object library dependencies cannot be propagated
        # so as a workaround explicitly specify it here.
        foreach(libname IN LISTS STATIC_FILES)
                list(APPEND SOURCES $<TARGET_OBJECTS:${libname}>)
        endforeach()
        # Older CMake versions forbid library dependencies on object libraries,
        # therefore repeat softhsm_crypto and softhsm_objectstore dependencies.
        set(STATIC_FILES ${CRYPTO_LIBS} ${SQLITE3_LIBS})
endif()


if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/win32)
	list(APPEND STATIC_FILES "Ws2_32.lib;Crypt32.lib")
ENDIF()


include_directories(${INCLUDE_DIRS})

###############################################################################
# Static Library Config
###############################################################################
add_library(${PROJECT_NAME}-static STATIC ${SOURCES})
target_link_libraries(${PROJECT_NAME}-static ${STATIC_FILES})
set_target_properties(${PROJECT_NAME}-static
                      PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-static
                      )
generate_export_header(${PROJECT_NAME}-static)
target_compile_options(${PROJECT_NAME}-static PRIVATE ${COMPILE_OPTIONS})

###############################################################################
# Shared Library Config
###############################################################################
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${STATIC_FILES})
generate_export_header(${PROJECT_NAME})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

###############################################################################
# Emscripten WASM Target
# Produces softhsmv3.js + softhsmv3.wasm (MODULARIZE=1, factory: createSoftHSMModule)
###############################################################################
if(EMSCRIPTEN)
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".js")

    # Complete list of all PKCS#11 v2.0 / v3.0 / v3.2 C_* functions (71 total)
    set(PKCS11_EXPORTS
        "_C_Initialize,_C_Finalize,_C_GetInfo,_C_GetFunctionList,"
        "_C_GetSlotList,_C_GetSlotInfo,_C_GetTokenInfo,"
        "_C_GetMechanismList,_C_GetMechanismInfo,"
        "_C_InitToken,_C_InitPIN,_C_SetPIN,"
        "_C_OpenSession,_C_CloseSession,_C_CloseAllSessions,"
        "_C_GetSessionInfo,_C_GetOperationState,_C_SetOperationState,"
        "_C_Login,_C_Logout,"
        "_C_CreateObject,_C_CopyObject,_C_DestroyObject,_C_GetObjectSize,"
        "_C_GetAttributeValue,_C_SetAttributeValue,"
        "_C_FindObjectsInit,_C_FindObjects,_C_FindObjectsFinal,"
        "_C_EncryptInit,_C_Encrypt,_C_EncryptUpdate,_C_EncryptFinal,"
        "_C_DecryptInit,_C_Decrypt,_C_DecryptUpdate,_C_DecryptFinal,"
        "_C_DigestInit,_C_Digest,_C_DigestUpdate,_C_DigestKey,_C_DigestFinal,"
        "_C_SignInit,_C_Sign,_C_SignUpdate,_C_SignFinal,"
        "_C_SignRecoverInit,_C_SignRecover,"
        "_C_VerifyInit,_C_Verify,_C_VerifyUpdate,_C_VerifyFinal,"
        "_C_VerifyRecoverInit,_C_VerifyRecover,"
        "_C_DigestEncryptUpdate,_C_DecryptDigestUpdate,"
        "_C_SignEncryptUpdate,_C_DecryptVerifyUpdate,"
        "_C_GenerateKey,_C_GenerateKeyPair,"
        "_C_WrapKey,_C_UnwrapKey,_C_DeriveKey,"
        "_C_SeedRandom,_C_GenerateRandom,"
        "_C_GetFunctionStatus,_C_CancelFunction,_C_WaitForSlotEvent,"
        "_C_GetInterfaceList,_C_GetInterface,_C_LoginUser,_C_SessionCancel,"
        "_C_MessageEncryptInit,_C_EncryptMessage,"
        "_C_EncryptMessageBegin,_C_EncryptMessageNext,_C_MessageEncryptFinal,"
        "_C_MessageDecryptInit,_C_DecryptMessage,"
        "_C_DecryptMessageBegin,_C_DecryptMessageNext,_C_MessageDecryptFinal,"
        "_C_MessageSignInit,_C_SignMessage,"
        "_C_SignMessageBegin,_C_SignMessageNext,_C_MessageSignFinal,"
        "_C_MessageVerifyInit,_C_VerifyMessage,"
        "_C_VerifyMessageBegin,_C_VerifyMessageNext,_C_MessageVerifyFinal,"
        "_C_EncapsulateKey,_C_DecapsulateKey,"
        "_C_VerifySignatureInit,_C_VerifySignature,"
        "_C_VerifySignatureUpdate,_C_VerifySignatureFinal,"
        "_C_GetSessionValidationFlags,"
        "_C_AsyncComplete,_C_AsyncGetID,_C_AsyncJoin,"
        "_C_WrapKeyAuthenticated,_C_UnwrapKeyAuthenticated,"
        "_malloc,_free"
    )
    string(CONCAT PKCS11_EXPORTS_STR ${PKCS11_EXPORTS})

    target_link_options(${PROJECT_NAME} PRIVATE
        # 2026-07-29: explicit opt-out, required since emsdk 6.0.4. Emscripten's
        # linker now defaults SIDE_MODULE=1 whenever `-shared` is on the command
        # line (CMake always passes `-shared` for a SHARED library target), which
        # broke this build: EXPORTED_FUNCTIONS became a no-op, "_free" could no
        # longer be resolved as an export, and only a bare .wasm was emitted (no
        # .js). This target was never a WASM dynamic-linking side module — it's a
        # standalone MODULARIZE JS+WASM blob (createSoftHSMModule) — so force the
        # old "main module" style linking back on.
        "-sSIDE_MODULE=0"
        "-sMODULARIZE=1"
        "-sEXPORT_NAME=createSoftHSMModule"
        "-sEXPORTED_FUNCTIONS=[${PKCS11_EXPORTS_STR}]"
        "-sEXPORTED_RUNTIME_METHODS=['FS','getValue','setValue','UTF8ToString','stringToUTF8','lengthBytesUTF8','HEAPU8','HEAP32']"
        "-sALLOW_MEMORY_GROWTH=1"
        "-sINITIAL_MEMORY=67108864"
        "-sMAXIMUM_MEMORY=536870912"
        "-sFORCE_FILESYSTEM=1"
        "-sENVIRONMENT=node,web"
        "--pre-js" "${CMAKE_SOURCE_DIR}/src/wasm/softhsm_pre.js"
    )
endif()

###############################################################################
# Tests
###############################################################################
if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)

###############################################################################
# Install
###############################################################################
install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/softhsm
        )
if(ENABLE_STATIC)
        install(TARGETS ${PROJECT_NAME}-static
                DESTINATION ${CMAKE_INSTALL_LIBDIR}/softhsm
                )
endif()

# Install public PKCS#11 headers so C/C++ consumers can link without
# manually copying headers (fixes OSS gap C1).
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/pkcs11.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/pkcs11f.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/pkcs11t.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/cryptoki.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/softhsm
        )
