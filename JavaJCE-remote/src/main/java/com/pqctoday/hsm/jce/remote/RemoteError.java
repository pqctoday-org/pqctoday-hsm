package com.pqctoday.hsm.jce.remote;

import io.grpc.StatusRuntimeException;

import java.security.ProviderException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * gRPC {@link StatusRuntimeException} -&gt; {@code CKR_*}-named
 * {@link ProviderException} mapping — the remote counterpart to
 * {@code P11Error} in {@code ../../JavaJCE/}'s own package (not reused
 * directly: that class is package-private to
 * {@code com.pqctoday.hsm.jce}, a deliberate internal-implementation
 * boundary this module doesn't cross, and its 105-entry table covers
 * every CK_RV the LOCAL PKCS#11 surface can produce — this remote
 * surface can only ever produce the narrower set
 * {@code remoting/proto/proto/pkcs11_remote.proto}'s own
 * {@code Pkcs11Error} enum names, confirmed by reading
 * {@code remoting/grpc/src/error.rs::classify} directly).
 *
 * The real {@code raw_ck_rv} value is never carried as a structured gRPC
 * status detail — confirmed reading {@code error.rs}'s own doc comment
 * (plan §7 E0's own finding, 2026-08-25): it's embedded as a
 * {@code raw_ck_rv=0x...} substring inside the plain
 * {@link io.grpc.Status#getDescription()} text, so this class parses it
 * out with a regex rather than deserializing a typed object — the exact
 * same parsing {@code remoting/acceptance/tests/three_way_parity.rs}'s
 * own {@code grpc_raw_ck_rv} helper already does, mirrored here rather
 * than reinvented from a guess.
 */
final class RemoteError {
    private RemoteError() {}

    private static final Pattern RAW_CK_RV = Pattern.compile("raw_ck_rv=0x([0-9A-Fa-f]+)");

    // Only the codes this remote surface can actually produce — confirmed
    // against remoting/proto/proto/pkcs11_remote.proto's own Pkcs11Error
    // enum, not the full local-provider CK_RV table.
    private static final Map<Long, String> NAMES = Map.ofEntries(
        Map.entry(0x00000005L, "CKR_GENERAL_ERROR"),
        Map.entry(0x00000006L, "CKR_FUNCTION_FAILED"),
        Map.entry(0x00000007L, "CKR_ARGUMENTS_BAD"),
        Map.entry(0x00000013L, "CKR_ATTRIBUTE_VALUE_INVALID"),
        Map.entry(0x00000063L, "CKR_KEY_TYPE_INCONSISTENT"),
        Map.entry(0x00000068L, "CKR_KEY_FUNCTION_NOT_PERMITTED"),
        Map.entry(0x00000070L, "CKR_MECHANISM_INVALID"),
        Map.entry(0x000000A0L, "CKR_PIN_INCORRECT"),
        Map.entry(0x000000B3L, "CKR_SESSION_HANDLE_INVALID"),
        Map.entry(0x000000C0L, "CKR_SIGNATURE_INVALID"),
        Map.entry(0x000000D0L, "CKR_TEMPLATE_INCOMPLETE")
    );

    /** The real numeric {@code raw_ck_rv}, or {@code -1} if the status carried none (a non-PKCS#11 transport fault). */
    static long rawCkRv(StatusRuntimeException e) {
        String desc = e.getStatus().getDescription();
        if (desc == null) return -1;
        Matcher m = RAW_CK_RV.matcher(desc);
        if (!m.find()) return -1;
        try {
            return Long.parseLong(m.group(1), 16);
        } catch (NumberFormatException nfe) {
            return -1;
        }
    }

    static String name(long rv) {
        String n = NAMES.get(rv);
        return n != null ? n : "UNKNOWN";
    }

    /** Wraps a {@link StatusRuntimeException} into a {@link ProviderException} naming the real {@code CKR_*} value when present. */
    static ProviderException wrap(StatusRuntimeException e) {
        long rv = rawCkRv(e);
        if (rv < 0) {
            return new ProviderException("gRPC call failed: " + e.getStatus(), e);
        }
        return new ProviderException(
            "gRPC call failed: " + name(rv) + " (0x" + Long.toHexString(rv) + "): " + e.getStatus().getDescription(),
            e);
    }
}
