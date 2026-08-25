package com.pqctoday.hsm.jce;

import java.security.ProviderException;
import java.util.HashMap;
import java.util.Map;

/**
 * CK_RV -> JCA exception mapping. Every native call in this provider goes
 * through {@link #check}; no CK_RV is ever silently ignored (audit standard
 * used throughout this repo — see the compliance-testing remediation work
 * in CHANGELOG.md for what "silently-dropped errors" cost when missed).
 *
 * Table generated from src/lib/pkcs11/pkcs11t.h (105 codes, 2026-08-24) —
 * this file is the ONLY source of truth for CK_RV values per this repo's
 * CLAUDE.md; do not hand-edit values here without regenerating from it.
 */
final class P11Error {
    private P11Error() {}

    static final long CKR_OK = 0x00000000L;

    private static final Map<Long, String> NAMES = new HashMap<>();
    static {
        Map<Long, String> m = NAMES;
        m.put(0x00000000L, "CKR_OK");
        m.put(0x00000001L, "CKR_CANCEL");
        m.put(0x00000002L, "CKR_HOST_MEMORY");
        m.put(0x00000003L, "CKR_SLOT_ID_INVALID");
        m.put(0x00000005L, "CKR_GENERAL_ERROR");
        m.put(0x00000006L, "CKR_FUNCTION_FAILED");
        m.put(0x00000007L, "CKR_ARGUMENTS_BAD");
        m.put(0x00000008L, "CKR_NO_EVENT");
        m.put(0x00000009L, "CKR_NEED_TO_CREATE_THREADS");
        m.put(0x0000000aL, "CKR_CANT_LOCK");
        m.put(0x00000010L, "CKR_ATTRIBUTE_READ_ONLY");
        m.put(0x00000011L, "CKR_ATTRIBUTE_SENSITIVE");
        m.put(0x00000012L, "CKR_ATTRIBUTE_TYPE_INVALID");
        m.put(0x00000013L, "CKR_ATTRIBUTE_VALUE_INVALID");
        m.put(0x0000001bL, "CKR_ACTION_PROHIBITED");
        m.put(0x00000020L, "CKR_DATA_INVALID");
        m.put(0x00000021L, "CKR_DATA_LEN_RANGE");
        m.put(0x00000030L, "CKR_DEVICE_ERROR");
        m.put(0x00000031L, "CKR_DEVICE_MEMORY");
        m.put(0x00000032L, "CKR_DEVICE_REMOVED");
        m.put(0x00000040L, "CKR_ENCRYPTED_DATA_INVALID");
        m.put(0x00000041L, "CKR_ENCRYPTED_DATA_LEN_RANGE");
        m.put(0x00000042L, "CKR_AEAD_DECRYPT_FAILED");
        m.put(0x00000050L, "CKR_FUNCTION_CANCELED");
        m.put(0x00000051L, "CKR_FUNCTION_NOT_PARALLEL");
        m.put(0x00000054L, "CKR_FUNCTION_NOT_SUPPORTED");
        m.put(0x00000060L, "CKR_KEY_HANDLE_INVALID");
        m.put(0x00000062L, "CKR_KEY_SIZE_RANGE");
        m.put(0x00000063L, "CKR_KEY_TYPE_INCONSISTENT");
        m.put(0x00000064L, "CKR_KEY_NOT_NEEDED");
        m.put(0x00000065L, "CKR_KEY_CHANGED");
        m.put(0x00000066L, "CKR_KEY_NEEDED");
        m.put(0x00000067L, "CKR_KEY_INDIGESTIBLE");
        m.put(0x00000068L, "CKR_KEY_FUNCTION_NOT_PERMITTED");
        m.put(0x00000069L, "CKR_KEY_NOT_WRAPPABLE");
        m.put(0x0000006aL, "CKR_KEY_UNEXTRACTABLE");
        m.put(0x00000070L, "CKR_MECHANISM_INVALID");
        m.put(0x00000071L, "CKR_MECHANISM_PARAM_INVALID");
        m.put(0x00000082L, "CKR_OBJECT_HANDLE_INVALID");
        m.put(0x00000090L, "CKR_OPERATION_ACTIVE");
        m.put(0x00000091L, "CKR_OPERATION_NOT_INITIALIZED");
        m.put(0x000000a0L, "CKR_PIN_INCORRECT");
        m.put(0x000000a1L, "CKR_PIN_INVALID");
        m.put(0x000000a2L, "CKR_PIN_LEN_RANGE");
        m.put(0x000000a3L, "CKR_PIN_EXPIRED");
        m.put(0x000000a4L, "CKR_PIN_LOCKED");
        m.put(0x000000b0L, "CKR_SESSION_CLOSED");
        m.put(0x000000b1L, "CKR_SESSION_COUNT");
        m.put(0x000000b3L, "CKR_SESSION_HANDLE_INVALID");
        m.put(0x000000b4L, "CKR_SESSION_PARALLEL_NOT_SUPPORTED");
        m.put(0x000000b5L, "CKR_SESSION_READ_ONLY");
        m.put(0x000000b6L, "CKR_SESSION_EXISTS");
        m.put(0x000000b7L, "CKR_SESSION_READ_ONLY_EXISTS");
        m.put(0x000000b8L, "CKR_SESSION_READ_WRITE_SO_EXISTS");
        m.put(0x000000c0L, "CKR_SIGNATURE_INVALID");
        m.put(0x000000c1L, "CKR_SIGNATURE_LEN_RANGE");
        m.put(0x000000d0L, "CKR_TEMPLATE_INCOMPLETE");
        m.put(0x000000d1L, "CKR_TEMPLATE_INCONSISTENT");
        m.put(0x000000e0L, "CKR_TOKEN_NOT_PRESENT");
        m.put(0x000000e1L, "CKR_TOKEN_NOT_RECOGNIZED");
        m.put(0x000000e2L, "CKR_TOKEN_WRITE_PROTECTED");
        m.put(0x000000f0L, "CKR_UNWRAPPING_KEY_HANDLE_INVALID");
        m.put(0x000000f1L, "CKR_UNWRAPPING_KEY_SIZE_RANGE");
        m.put(0x000000f2L, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
        m.put(0x00000100L, "CKR_USER_ALREADY_LOGGED_IN");
        m.put(0x00000101L, "CKR_USER_NOT_LOGGED_IN");
        m.put(0x00000102L, "CKR_USER_PIN_NOT_INITIALIZED");
        m.put(0x00000103L, "CKR_USER_TYPE_INVALID");
        m.put(0x00000104L, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
        m.put(0x00000105L, "CKR_USER_TOO_MANY_TYPES");
        m.put(0x00000110L, "CKR_WRAPPED_KEY_INVALID");
        m.put(0x00000112L, "CKR_WRAPPED_KEY_LEN_RANGE");
        m.put(0x00000113L, "CKR_WRAPPING_KEY_HANDLE_INVALID");
        m.put(0x00000114L, "CKR_WRAPPING_KEY_SIZE_RANGE");
        m.put(0x00000115L, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT");
        m.put(0x00000120L, "CKR_RANDOM_SEED_NOT_SUPPORTED");
        m.put(0x00000121L, "CKR_RANDOM_NO_RNG");
        m.put(0x00000130L, "CKR_DOMAIN_PARAMS_INVALID");
        m.put(0x00000140L, "CKR_CURVE_NOT_SUPPORTED");
        m.put(0x00000150L, "CKR_BUFFER_TOO_SMALL");
        m.put(0x00000160L, "CKR_SAVED_STATE_INVALID");
        m.put(0x00000170L, "CKR_INFORMATION_SENSITIVE");
        m.put(0x00000180L, "CKR_STATE_UNSAVEABLE");
        m.put(0x00000190L, "CKR_CRYPTOKI_NOT_INITIALIZED");
        m.put(0x00000191L, "CKR_CRYPTOKI_ALREADY_INITIALIZED");
        m.put(0x000001a0L, "CKR_MUTEX_BAD");
        m.put(0x000001a1L, "CKR_MUTEX_NOT_LOCKED");
        m.put(0x000001b0L, "CKR_NEW_PIN_MODE");
        m.put(0x000001b1L, "CKR_NEXT_OTP");
        m.put(0x000001b5L, "CKR_EXCEEDED_MAX_ITERATIONS");
        m.put(0x000001b6L, "CKR_FIPS_SELF_TEST_FAILED");
        m.put(0x000001b7L, "CKR_LIBRARY_LOAD_FAILED");
        m.put(0x000001b8L, "CKR_PIN_TOO_WEAK");
        m.put(0x000001b9L, "CKR_PUBLIC_KEY_INVALID");
        m.put(0x00000200L, "CKR_FUNCTION_REJECTED");
        m.put(0x00000201L, "CKR_TOKEN_RESOURCE_EXCEEDED");
        m.put(0x00000202L, "CKR_OPERATION_CANCEL_FAILED");
        m.put(0x00000203L, "CKR_KEY_EXHAUSTED");
        m.put(0x00000204L, "CKR_PENDING");
        m.put(0x00000205L, "CKR_SESSION_ASYNC_NOT_SUPPORTED");
        m.put(0x00000206L, "CKR_SEED_RANDOM_REQUIRED");
        m.put(0x00000207L, "CKR_OPERATION_NOT_VALIDATED");
        m.put(0x00000208L, "CKR_TOKEN_NOT_INITIALIZED");
        m.put(0x00000209L, "CKR_PARAMETER_SET_NOT_SUPPORTED");
        m.put(0x80000000L, "CKR_VENDOR_DEFINED");
    }

    static String name(long rv) {
        String n = NAMES.get(rv);
        return n != null ? n : "UNKNOWN";
    }

    /** Throws if rv != CKR_OK. Every native call site must route through this. */
    static void check(long rv, String call) {
        if (rv != CKR_OK) {
            throw new ProviderException(call + " failed: " + name(rv) + " (0x" + Long.toHexString(rv) + ")");
        }
    }
}
