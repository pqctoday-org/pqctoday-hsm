// KAT parity harness for the softhsmrustv3 wasm engine.
// Every section drives the REAL wasm ABI and compares against published
// known-answer vectors (NIST / RFC). No section may print a pass without
// computing the value through the engine.
//
// Run: node test_kat_parity.js   (requires pkg/ built via wasm-pack)
'use strict';
const fs = require('fs');
const crypto = require('crypto');

// ── NIST AES-256 CTR-DRBG (deterministic seed expansion for the XMSS KAT) ───
class AES_256_CTR_DRBG {
    constructor(entropy_hex) {
        if (entropy_hex.length !== 96) throw new Error("Entropy must be 48 bytes (96 hex chars)");
        this.Key = Buffer.alloc(32, 0);
        this.V = Buffer.alloc(16, 0);
        this.update(Buffer.from(entropy_hex, 'hex'));
    }
    update(provided_data) {
        let temp = Buffer.alloc(48);
        for (let i = 0; i < 3; i++) {
            for (let j = 15; j >= 0; j--) {
                this.V[j]++;
                if (this.V[j] !== 0) break;
            }
            const cipher = crypto.createCipheriv('aes-256-ecb', this.Key, null);
            cipher.setAutoPadding(false);
            const enc = cipher.update(this.V);
            enc.copy(temp, i * 16);
        }
        if (provided_data) {
            for (let i = 0; i < 48; i++) {
                temp[i] ^= provided_data[i];
            }
        }
        this.Key = temp.subarray(0, 32);
        this.V = temp.subarray(32, 48);
    }
    generate(out_len) {
        let out = Buffer.alloc(out_len);
        let temp = Buffer.alloc(Math.ceil(out_len / 16) * 16);
        let blocks = temp.length / 16;
        for (let i = 0; i < blocks; i++) {
            for (let j = 15; j >= 0; j--) {
                this.V[j]++;
                if (this.V[j] !== 0) break;
            }
            const cipher = crypto.createCipheriv('aes-256-ecb', this.Key, null);
            cipher.setAutoPadding(false);
            const enc = cipher.update(this.V);
            enc.copy(temp, i * 16);
        }
        temp.copy(out, 0, 0, out_len);
        this.update(null);
        return out;
    }
}

const kat_drbg = new AES_256_CTR_DRBG("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");

// ── module load ──────────────────────────────────────────────────────────────
const wasmBuf = fs.readFileSync(__dirname + '/pkg/softhsmrustv3_bg.wasm');
const bg = require('./pkg/softhsmrustv3_bg.js');

let wasmModule = new WebAssembly.Module(wasmBuf);
let wasmInstance = new WebAssembly.Instance(wasmModule, {
    "./softhsmrustv3_bg.js": bg
});
bg.__wbg_set_wasm(wasmInstance.exports);
const wasm = wasmInstance.exports;

// ── constants (values from pkcs11t.h / rust/src/constants.rs) ────────────────
const CKM_XMSS_KEY_PAIR_GEN = 0x00004034;
// Vendor attribute — rust/src/constants.rs: CKA_XMSS_PARAM_SET = 0x8000_0104
const CKA_XMSS_PARAM_SET = 0x80000104;
const CKP_XMSS_SHA2_10_256 = 0x00000001;
const CKA_CLASS = 0x000;
const CKA_TOKEN = 0x001;
const CKA_PRIVATE = 0x002;
const CKA_VALUE = 0x011;
const CKA_KEY_TYPE = 0x100;
const CKA_ENCRYPT = 0x104;
const CKA_DERIVE = 0x10c;
const CKA_VALUE_LEN = 0x161;
const CKO_PUBLIC_KEY = 2;
const CKO_PRIVATE_KEY = 3;
const CKO_SECRET_KEY = 4;
const CKK_GENERIC_SECRET = 0x10;
const CKK_CHACHA20 = 0x33;
const CKK_EC_MONTGOMERY = 0x41;
const CKM_SHA256 = 0x250;
// PKCS#11 v3.2 §6.26 — the SP 800-108 PRF must be a keyed-MAC mechanism
// (rust/src/constants.rs: CKM_SHA256_HMAC = 0x251).
const CKM_SHA256_HMAC = 0x251;
const CKM_CHACHA20_POLY1305 = 0x4021;
const CKM_SP800_108_COUNTER_KDF = 0x3ac;
// Vendor mechanism — rust/src/constants.rs: CKM_EC_MONTGOMERY_KEY_DERIVE
const CKM_EC_MONTGOMERY_KEY_DERIVE = 0x80000011;
const CKD_NULL = 0x1;
// Engine-internal algo-family routing attribute (rust/src/state.rs
// store_algo_family) — needed when IMPORTING an X25519 private key, because
// C_CreateObject cannot infer the Montgomery family from a raw CKA_VALUE.
const CKA_PRIV_ALGO_FAMILY = 0xFFFF0002;
const ALGO_ECDH_X25519 = 8;
const CK_SP800_108_ITERATION_VARIABLE = 0x1;
const CK_SP800_108_BYTE_ARRAY = 0x4;

// ── helpers ──────────────────────────────────────────────────────────────────
let passes = 0, failures = 0;
function report(label, ok, detail) {
    if (ok) { passes++; console.log(`       ✅ [PASS] ${label}`); }
    else {
        failures++;
        console.error(`       ❌ [FAIL] ${label}${detail ? ' — ' + detail : ''}`);
    }
}

function alloc(n) { return wasm._malloc(n); }
function writeBytes(ptr, bytes) { new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes); }
function readBytes(ptr, len) { return Buffer.from(new Uint8Array(wasm.memory.buffer, ptr, len)); }
function readU32(ptr) { return new Uint32Array(wasm.memory.buffer, ptr, 1)[0]; }
function writeU32(ptr, v) { new Uint32Array(wasm.memory.buffer, ptr, 1)[0] = v; }
function allocBytes(bytes) { const p = alloc(bytes.length); writeBytes(p, bytes); return p; }
function u32LE(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b; }

// CK_ATTRIBUTE[] — proper wasm32 layout: contiguous 12-byte records
// (type u32, pValue u32, ulValueLen u32); values live in separate buffers.
// Mirrors buildTpl in test_p11_conformance.js.
function buildTpl(attrs) {
    const ptr = alloc(attrs.length * 12);
    attrs.forEach((a, i) => {
        const base = ptr + i * 12;
        if (a.value && a.value.length) {
            const vp = allocBytes(a.value);
            writeU32(base, a.type); writeU32(base + 4, vp); writeU32(base + 8, a.value.length);
        } else {
            writeU32(base, a.type); writeU32(base + 4, 0); writeU32(base + 8, 0);
        }
    });
    return ptr;
}
// CK_MECHANISM — wasm32: mechanism u32, pParameter u32, ulParameterLen u32.
function buildMech(m, paramPtr, paramLen) {
    const p = alloc(12);
    writeU32(p, m); writeU32(p + 4, paramPtr || 0); writeU32(p + 8, paramLen || 0);
    return p;
}
// Read a byte attribute via the §5.2 two-call convention.
function getAttr(session, hObj, attrType) {
    const t = alloc(12);
    writeU32(t, attrType); writeU32(t + 4, 0); writeU32(t + 8, 0);
    let rv = wasm._C_GetAttributeValue(session, hObj, t, 1);
    if (rv !== 0) return { rv };
    const len = readU32(t + 8);
    const vp = alloc(len);
    writeU32(t + 4, vp); writeU32(t + 8, len);
    rv = wasm._C_GetAttributeValue(session, hObj, t, 1);
    return { rv, value: readBytes(vp, len) };
}

function run() {
    wasm._C_Initialize(0);

    let ptrSes = alloc(4);
    // CKF_RW_SESSION | CKF_SERIAL_SESSION (0x02 | 0x04) — SERIAL is mandatory per PKCS#11 §5.6
    wasm._C_OpenSession(0, 0x06, 0, 0, ptrSes);
    const session = readU32(ptrSes);

    // ═════ [1/4] XMSS keygen KAT (RFC 8391, deterministic DRBG seed) ═════════
    console.log("\n[1/4] XMSS Keygen KAT Parity Validation (NIST C++ golden vector)...");
    {
        // Inject deterministic KAT seed (matching the two-call sequence of xmss_core_fast.c)
        const block1 = kat_drbg.generate(64); // SK_SEED + SK_PRF
        const block2 = kat_drbg.generate(32); // PUB_SEED
        const seedBytes = Buffer.concat([block1, block2]);
        const ptrSeed = allocBytes(seedBytes);
        wasm._set_kat_seed(ptrSeed, 96);

        // CKM_XMSS_KEY_PAIR_GEN with CKP param word as mechanism parameter
        const mech = buildMech(CKM_XMSS_KEY_PAIR_GEN, allocBytes(u32LE(CKP_XMSS_SHA2_10_256)), 4);
        const pubTpl = buildTpl([{ type: CKA_XMSS_PARAM_SET, value: u32LE(CKP_XMSS_SHA2_10_256) }]);
        const prvTpl = buildTpl([{ type: CKA_XMSS_PARAM_SET, value: u32LE(CKP_XMSS_SHA2_10_256) }]);
        const ptrHPub = alloc(4), ptrHPrv = alloc(4);
        const rv = wasm._C_GenerateKeyPair(session, mech, pubTpl, 1, prvTpl, 1, ptrHPub, ptrHPrv);
        report('C_GenerateKeyPair(CKM_XMSS_KEY_PAIR_GEN) rv=0', rv === 0, `rv=0x${rv.toString(16)}`);

        const got = getAttr(session, readU32(ptrHPub), CKA_VALUE);
        report('C_GetAttributeValue(CKA_VALUE) rv=0', got.rv === 0, `rv=0x${got.rv.toString(16)}`);
        // RFC 8391 §4.1.7 XMSS public key: OID(4) || root(32) || PUB_SEED(32) = 68 bytes.
        // The OID prefix (00000001 = XMSS-SHA2_10_256) is part of the encoded key —
        // exact match REQUIRED, no prefix-stripped fallback.
        const expected =
            "000000013633A6CC7EC755BDECDF420CBA12D2BC51EBCBD03A5ECF7C34F539D2" +
            "CE74C3ABEB4A7C66EF4EBA2DDB38C88D8BC706B1D639002198172A7B1942ECA8" +
            "F6C001BA";
        const gotHex = got.value ? got.value.toString('hex').toUpperCase() : '';
        report('XMSS public key matches golden vector EXACTLY (68 bytes incl. OID)',
            gotHex === expected, `got ${gotHex}`);

        // clear the deterministic seed so later sections use the real RNG
        wasm._set_kat_seed(0, 0);
    }

    // ═════ [2/4] ChaCha20-Poly1305 KAT (RFC 7539 §2.8.2) ═════════════════════
    console.log("\n[2/4] ChaCha20-Poly1305 KAT Parity Validation (RFC 7539)...");
    {
        const chachaKey = Buffer.from(
            "808182838485868788898a8b8c8d8e8f" +
            "909192939495969798999a9b9c9d9e9f", "hex");
        const chachaNonce = Buffer.from("070000004041424344454647", "hex"); // 12 bytes
        const chachaAAD   = Buffer.from("50515253c0c1c2c3c4c5c6c7", "hex"); // 12 bytes
        const chachaPT    = Buffer.from(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373" +
            "206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c" +
            "79206f6e652074697020666f7220746865206675747572652c2073756e73637265" +
            "656e20776f756c6420626520697421", "hex"); // 114 bytes
        // Expected: 114-byte ciphertext || 16-byte Poly1305 tag = 130 bytes (RFC 7539 §2.8.2)
        const chachaExpected = Buffer.from(
            "d31a8d34648e60db7b86afbc53ef7ec2" +
            "a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b" +
            "1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803" +
            "aee328091b58fab324e4fad675945585" +
            "808b4831d7bc3ff4def08e4b7a9de576" +
            "d26586cec64b6119" +
            "580b557d51e386910e5de72060a715dc", "hex"); // 130 bytes

        const tpl = buildTpl([
            { type: CKA_CLASS,    value: u32LE(CKO_SECRET_KEY) },
            { type: CKA_KEY_TYPE, value: u32LE(CKK_CHACHA20) },
            { type: CKA_TOKEN,    value: Buffer.from([0x00]) },
            { type: CKA_ENCRYPT,  value: Buffer.from([0x01]) },
            { type: CKA_VALUE,    value: chachaKey },
        ]);
        const pHandle = alloc(4);
        const rvCreate = wasm._C_CreateObject(session, tpl, 5, pHandle);
        report('C_CreateObject(ChaCha20 key) rv=0', rvCreate === 0, `rv=0x${rvCreate.toString(16)}`);

        if (rvCreate === 0) {
            // CK_SALSA20_CHACHA20_POLY1305_PARAMS (wasm32, 16 B): pNonce, ulNonceLen, pAAD, ulAADLen
            const pParams = alloc(16);
            new Uint32Array(wasm.memory.buffer, pParams, 4).set([
                allocBytes(chachaNonce), 12, allocBytes(chachaAAD), 12]);
            const mech = buildMech(CKM_CHACHA20_POLY1305, pParams, 16);

            const rvInit = wasm._C_EncryptInit(session, mech, readU32(pHandle));
            report('C_EncryptInit(CKM_CHACHA20_POLY1305) rv=0', rvInit === 0, `rv=0x${rvInit.toString(16)}`);
            if (rvInit === 0) {
                const pPlain = allocBytes(chachaPT);
                const pCipher = alloc(256);
                const pCipherLen = alloc(4);
                writeU32(pCipherLen, 256);
                const rvEnc = wasm._C_Encrypt(session, pPlain, chachaPT.length, pCipher, pCipherLen);
                const cipherLen = readU32(pCipherLen);
                const gotCT = readBytes(pCipher, cipherLen);
                report('ChaCha20-Poly1305 ciphertext||tag matches RFC 7539 KAT (130 bytes)',
                    rvEnc === 0 && cipherLen === 130 && gotCT.equals(chachaExpected),
                    `rv=0x${rvEnc.toString(16)} len=${cipherLen} got=${gotCT.toString('hex')}`);
            }
        }
    }

    // ═════ [3/4] X25519 ECDH KAT (RFC 7748 §6.1) ═════════════════════════════
    console.log("\n[3/4] X25519 KAT Parity Validation (RFC 7748 §6.1)...");
    {
        // Alice's private scalar / Bob's public key / expected shared secret K
        const alicePriv = Buffer.from(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "hex");
        const bobPub = Buffer.from(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "hex");
        const expectedK =
            "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742";

        const tpl = buildTpl([
            { type: CKA_CLASS,            value: u32LE(CKO_PRIVATE_KEY) },
            { type: CKA_KEY_TYPE,         value: u32LE(CKK_EC_MONTGOMERY) },
            { type: CKA_TOKEN,            value: Buffer.from([0x00]) },
            { type: CKA_PRIVATE,          value: Buffer.from([0x00]) }, // harness never logs in
            { type: CKA_DERIVE,           value: Buffer.from([0x01]) },
            { type: CKA_VALUE,            value: alicePriv },
            { type: CKA_PRIV_ALGO_FAMILY, value: u32LE(ALGO_ECDH_X25519) },
        ]);
        const pHandle = alloc(4);
        const rvCreate = wasm._C_CreateObject(session, tpl, 7, pHandle);
        report('C_CreateObject(X25519 private key) rv=0', rvCreate === 0, `rv=0x${rvCreate.toString(16)}`);

        if (rvCreate === 0) {
            // CK_ECDH1_DERIVE_PARAMS (wasm32, 20 B): kdf, ulSharedDataLen, pSharedData,
            // ulPublicDataLen, pPublicData
            const pParams = alloc(20);
            new Uint32Array(wasm.memory.buffer, pParams, 5).set([
                CKD_NULL, 0, 0, 32, allocBytes(bobPub)]);
            const mech = buildMech(CKM_EC_MONTGOMERY_KEY_DERIVE, pParams, 20);
            const dTpl = buildTpl([
                { type: CKA_CLASS,     value: u32LE(CKO_SECRET_KEY) },
                { type: CKA_KEY_TYPE,  value: u32LE(CKK_GENERIC_SECRET) },
                { type: CKA_VALUE_LEN, value: u32LE(32) },
            ]);
            const pDerived = alloc(4);
            const rvDerive = wasm._C_DeriveKey(session, mech, readU32(pHandle), dTpl, 3, pDerived);
            report('C_DeriveKey(CKM_EC_MONTGOMERY_KEY_DERIVE) rv=0', rvDerive === 0, `rv=0x${rvDerive.toString(16)}`);
            if (rvDerive === 0) {
                const got = getAttr(session, readU32(pDerived), CKA_VALUE);
                const gotHex = got.value ? got.value.toString('hex').toUpperCase() : '';
                report('X25519 shared secret matches RFC 7748 §6.1 K EXACTLY',
                    got.rv === 0 && gotHex === expectedK, `got ${gotHex}`);
            }
        }
    }

    // ═════ [4/4] SP800-108 Counter-Mode KDF KAT (NIST CAVP KBKDF) ═════════════
    console.log("\n[4/4] SP800-108 Counter KDF KAT Validation (NIST CAVP)...");
    {
        // NIST CAVS 14.4 "SP800-108 - KDF" KBKDF CTR vector:
        // [PRF=HMAC_SHA256] [CTRLOCATION=BEFORE_FIXED] [RLEN=8_BITS] COUNT=0, L=128
        const KI = Buffer.from(
            "3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83", "hex");
        const fixedInput = Buffer.from(
            "98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80" +
            "c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a", "hex"); // 60 bytes
        const expectedKO = "6c037652990674a07844732d0ad985f9"; // 16 bytes

        const tpl = buildTpl([
            { type: CKA_CLASS,    value: u32LE(CKO_SECRET_KEY) },
            { type: CKA_KEY_TYPE, value: u32LE(CKK_GENERIC_SECRET) },
            { type: CKA_TOKEN,    value: Buffer.from([0x00]) },
            { type: CKA_PRIVATE,  value: Buffer.from([0x00]) },
            { type: CKA_DERIVE,   value: Buffer.from([0x01]) },
            { type: CKA_VALUE,    value: KI },
        ]);
        const pHandle = alloc(4);
        const rvCreate = wasm._C_CreateObject(session, tpl, 6, pHandle);
        report('C_CreateObject(KBKDF base key) rv=0', rvCreate === 0, `rv=0x${rvCreate.toString(16)}`);

        if (rvCreate === 0) {
            // CK_SP800_108_COUNTER_FORMAT (wasm32, 8 B): bLittleEndian u8 + pad3, ulWidthInBits u32
            const ctrFmt = Buffer.alloc(8);
            ctrFmt.writeUInt32LE(8, 4); // big-endian, 8-bit counter (RLEN=8_BITS)
            // CK_PRF_DATA_PARAM[2] (wasm32, 12 B each): type, pValue, ulValueLen
            const pSegs = alloc(24);
            new Uint32Array(wasm.memory.buffer, pSegs, 6).set([
                CK_SP800_108_ITERATION_VARIABLE, allocBytes(ctrFmt), 8,
                CK_SP800_108_BYTE_ARRAY, allocBytes(fixedInput), fixedInput.length,
            ]);
            // CK_SP800_108_KDF_PARAMS (wasm32): prfType, ulNumberOfDataParams, pDataParams
            const pParams = alloc(12);
            new Uint32Array(wasm.memory.buffer, pParams, 3).set([CKM_SHA256_HMAC, 2, pSegs]);
            const mech = buildMech(CKM_SP800_108_COUNTER_KDF, pParams, 12);
            const dTpl = buildTpl([
                { type: CKA_CLASS,     value: u32LE(CKO_SECRET_KEY) },
                { type: CKA_KEY_TYPE,  value: u32LE(CKK_GENERIC_SECRET) },
                { type: CKA_VALUE_LEN, value: u32LE(16) }, // L=128 bits
            ]);
            const pDerived = alloc(4);
            const rvDerive = wasm._C_DeriveKey(session, mech, readU32(pHandle), dTpl, 3, pDerived);
            report('C_DeriveKey(CKM_SP800_108_COUNTER_KDF) rv=0', rvDerive === 0, `rv=0x${rvDerive.toString(16)}`);
            if (rvDerive === 0) {
                const got = getAttr(session, readU32(pDerived), CKA_VALUE);
                const gotHex = got.value ? got.value.toString('hex') : '';
                report('SP800-108 CTR-HMAC-SHA256 KO matches NIST CAVP vector EXACTLY',
                    got.rv === 0 && gotHex === expectedKO, `got ${gotHex}`);
            }
        }
    }

    console.log(`\n════════ RESULT: ${passes} passed, ${failures} failed ════════`);
    process.exit(failures === 0 ? 0 : 1);
}
run();
