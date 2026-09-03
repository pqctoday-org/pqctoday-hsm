// ============================================================================
// scenarios.inc — the call sequences both engines are driven through.
//
// Included by p11_diff.cpp. Kept in a separate file so the harness mechanics
// and the behaviour under test can be read independently.
//
// Coverage is deliberately weighted to where the 2026-08-13 audit found real
// defects:
//   group "env"      — advertised surface: mechanisms, interfaces, profiles
//   group "create"   — the attribute set after EVERY object-creation path
//   group "encoding" — the byte encodings fixed in Phase 3
//   group "bytes"    — deterministic outputs that MUST be byte-identical
//   group "errors"   — the error codes fixed in Phase 4
//   group "security" — the Phase 1 invariants observable through the API
// ============================================================================

// --- shared parameter-set constants (values from src/lib/pkcs11/pkcs11t.h) ---
static CK_ULONG psMlKem768   = 2;   // CKP_ML_KEM_768
static CK_ULONG psMlDsa44    = 1;   // CKP_ML_DSA_44
static CK_ULONG psSlhSha2128s = 1;  // CKP_SLH_DSA_SHA2_128S
static CK_ULONG psXmssSha2_10_256 = 1; // CKP_XMSS_SHA2_10_256

static CK_KEY_TYPE ktEc       = CKK_EC;
static CK_KEY_TYPE ktEdwards  = CKK_EC_EDWARDS;
static CK_KEY_TYPE ktMont     = CKK_EC_MONTGOMERY;
static CK_KEY_TYPE ktRsa      = CKK_RSA;
static CK_KEY_TYPE ktMlDsa    = CKK_ML_DSA;
static CK_KEY_TYPE ktMlKem    = CKK_ML_KEM;

static CK_BYTE kLabel[] = "p11diff";
static CK_BYTE kId[]    = {0xd1, 0xff};

// A key pair generated inside a scenario, so both halves can be probed.
struct Pair { CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE; };

// Generate a key pair and record the return code plus BOTH attribute sets.
static Pair gen_pair(Engine& e, Recorder& r, CK_SESSION_HANDLE s, const std::string& tag,
                     CK_MECHANISM_TYPE mech,
                     CK_ATTRIBUTE* pubT, CK_ULONG pubN,
                     CK_ATTRIBUTE* privT, CK_ULONG privN) {
    CK_MECHANISM m = { mech, NULL_PTR, 0 };
    Pair p;
    CK_RV rv = e.fl->C_GenerateKeyPair(s, &m, pubT, pubN, privT, privN, &p.pub, &p.priv);
    r.rv(tag, rv);
    if (rv != CKR_OK) return p;
    record_attrs(e, r, tag + ".pub",  s, p.pub);
    record_attrs(e, r, tag + ".priv", s, p.priv);
    return p;
}

static CK_OBJECT_HANDLE gen_key(Engine& e, Recorder& r, CK_SESSION_HANDLE s, const std::string& tag,
                                CK_MECHANISM_TYPE mech, CK_ATTRIBUTE* t, CK_ULONG n) {
    CK_MECHANISM m = { mech, NULL_PTR, 0 };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = e.fl->C_GenerateKey(s, &m, t, n, &h);
    r.rv(tag, rv);
    if (rv == CKR_OK) record_attrs(e, r, tag + ".key", s, h);
    return h;
}

// Import the fixed AES-256 key. Deterministic input is what makes every
// ciphertext below comparable byte for byte across engines.
static CK_OBJECT_HANDLE make_fixed_aes(Engine& e, CK_SESSION_HANDLE s, bool extractable,
                                       CK_BBOOL* sensitive, CK_RV* out_rv = nullptr) {
    CK_BBOOL ext = extractable ? CK_TRUE : CK_FALSE;
    CK_ATTRIBUTE t[] = {
        ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
        ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
        ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
        ATTR(CKA_VALUE,       kFixedAes, sizeof kFixedAes),
        ATTR(CKA_ENCRYPT,     &bTrue,    sizeof bTrue),
        ATTR(CKA_DECRYPT,     &bTrue,    sizeof bTrue),
        ATTR(CKA_WRAP,        &bTrue,    sizeof bTrue),
        ATTR(CKA_UNWRAP,      &bTrue,    sizeof bTrue),
        ATTR(CKA_SIGN,        &bTrue,    sizeof bTrue),
        ATTR(CKA_VERIFY,      &bTrue,    sizeof bTrue),
        ATTR(CKA_EXTRACTABLE, &ext,      sizeof ext),
        ATTR(CKA_SENSITIVE,   sensitive, sizeof(CK_BBOOL)),
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_RV rv = e.fl->C_CreateObject(s, t, sizeof t / sizeof t[0], &h);
    if (out_rv) *out_rv = rv;
    return rv == CKR_OK ? h : CK_INVALID_HANDLE;
}

// ============================================================================
static void register_scenarios() {

// ---------------------------------------------------------------------------
// env — the advertised surface
// ---------------------------------------------------------------------------
add({"env.mechanism_set", "env",
     "Full C_GetMechanismList of both engines, one observation per mechanism",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         r.num("mech_count", e.mechs.size());
         for (CK_MECHANISM_TYPE m : e.mechs) r.put("mech." + mech_name(m), "present");
     }});

add({"env.mechanism_info_aes_cbc", "env",
     "CK_MECHANISM_INFO key-size range and flags for a mechanism both support",
     {CKM_AES_CBC}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         CK_MECHANISM_INFO mi; memset(&mi, 0, sizeof mi);
         CK_RV rv = e.fl->C_GetMechanismInfo(e.slot, CKM_AES_CBC, &mi);
         r.rv("info", rv);
         if (rv != CKR_OK) return;
         r.num("min", mi.ulMinKeySize); r.num("max", mi.ulMaxKeySize);
         static const NamePair fl_[] = {
             {CKF_HW,"CKF_HW"},{CKF_ENCRYPT,"CKF_ENCRYPT"},{CKF_DECRYPT,"CKF_DECRYPT"},
             {CKF_DIGEST,"CKF_DIGEST"},{CKF_SIGN,"CKF_SIGN"},{CKF_VERIFY,"CKF_VERIFY"},
             {CKF_GENERATE,"CKF_GENERATE"},{CKF_GENERATE_KEY_PAIR,"CKF_GENERATE_KEY_PAIR"},
             {CKF_WRAP,"CKF_WRAP"},{CKF_UNWRAP,"CKF_UNWRAP"},{CKF_DERIVE,"CKF_DERIVE"},
         };
         for (const auto& f : fl_) r.put(std::string("flag.") + f.n, (mi.flags & f.v) ? "1" : "0");
     }});

add({"env.library_info", "env", "C_GetInfo — versions, identity strings, flags",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         CK_INFO i; memset(&i, 0, sizeof i);
         r.rv("get_info", e.fl->C_GetInfo(&i));
         r.put("cryptoki_version", std::to_string(i.cryptokiVersion.major) + "." +
                                   std::to_string(i.cryptokiVersion.minor));
         r.put("library_version",  std::to_string(i.libraryVersion.major) + "." +
                                   std::to_string(i.libraryVersion.minor));
         r.num("flags", i.flags);
         r.put("manufacturerID",     std::string((char*)i.manufacturerID, 32));
         r.put("libraryDescription", std::string((char*)i.libraryDescription, 32));
     }});

add({"env.token_info", "env", "C_GetTokenInfo — flags decomposed bit by bit, plus capacities",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         CK_TOKEN_INFO t; memset(&t, 0, sizeof t);
         r.rv("get_token_info", e.fl->C_GetTokenInfo(e.slot, &t));
         static const NamePair fl_[] = {
             {CKF_RNG,"CKF_RNG"},{CKF_WRITE_PROTECTED,"CKF_WRITE_PROTECTED"},
             {CKF_LOGIN_REQUIRED,"CKF_LOGIN_REQUIRED"},
             {CKF_USER_PIN_INITIALIZED,"CKF_USER_PIN_INITIALIZED"},
             {CKF_RESTORE_KEY_NOT_NEEDED,"CKF_RESTORE_KEY_NOT_NEEDED"},
             {CKF_CLOCK_ON_TOKEN,"CKF_CLOCK_ON_TOKEN"},
             {CKF_PROTECTED_AUTHENTICATION_PATH,"CKF_PROTECTED_AUTHENTICATION_PATH"},
             {CKF_DUAL_CRYPTO_OPERATIONS,"CKF_DUAL_CRYPTO_OPERATIONS"},
             {CKF_TOKEN_INITIALIZED,"CKF_TOKEN_INITIALIZED"},
             {CKF_SECONDARY_AUTHENTICATION,"CKF_SECONDARY_AUTHENTICATION"},
             {CKF_USER_PIN_COUNT_LOW,"CKF_USER_PIN_COUNT_LOW"},
             {CKF_USER_PIN_FINAL_TRY,"CKF_USER_PIN_FINAL_TRY"},
             {CKF_USER_PIN_LOCKED,"CKF_USER_PIN_LOCKED"},
             {CKF_USER_PIN_TO_BE_CHANGED,"CKF_USER_PIN_TO_BE_CHANGED"},
             {CKF_SO_PIN_COUNT_LOW,"CKF_SO_PIN_COUNT_LOW"},
             {CKF_SO_PIN_FINAL_TRY,"CKF_SO_PIN_FINAL_TRY"},
             {CKF_SO_PIN_LOCKED,"CKF_SO_PIN_LOCKED"},
             {CKF_SO_PIN_TO_BE_CHANGED,"CKF_SO_PIN_TO_BE_CHANGED"},
             {CKF_ERROR_STATE,"CKF_ERROR_STATE"},
         };
         for (const auto& f : fl_) r.put(std::string("flag.") + f.n, (t.flags & f.v) ? "1" : "0");
         r.put("label", std::string((char*)t.label, 32));
         r.put("manufacturerID", std::string((char*)t.manufacturerID, 32));
         r.put("model", std::string((char*)t.model, 16));
         r.num("ulMinPinLen", t.ulMinPinLen);
         r.num("ulMaxPinLen", t.ulMaxPinLen);
         r.num("ulMaxSessionCount", t.ulMaxSessionCount);
         r.num("ulMaxRwSessionCount", t.ulMaxRwSessionCount);
         r.put("hardwareVersion", std::to_string(t.hardwareVersion.major) + "." +
                                  std::to_string(t.hardwareVersion.minor));
         r.put("firmwareVersion", std::to_string(t.firmwareVersion.major) + "." +
                                  std::to_string(t.firmwareVersion.minor));
     }});

add({"env.interfaces", "env", "C_GetInterfaceList — names, versions, flags and their order",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         typedef CK_RV (*GIL)(CK_INTERFACE_PTR, CK_ULONG_PTR);
         GIL gil = (GIL)dlsym(e.h, "C_GetInterfaceList");
         if (!gil) { r.put("C_GetInterfaceList", "ABSENT"); return; }
         CK_ULONG n = 0;
         r.rv("size_query", gil(NULL_PTR, &n));
         r.num("count", n);
         if (!n) return;
         std::vector<CK_INTERFACE> v(n);
         if (gil(v.data(), &n) != CKR_OK) return;
         for (CK_ULONG i = 0; i < n; i++) {
             CK_VERSION* ver = (CK_VERSION*)v[i].pFunctionList;
             char idx[8]; snprintf(idx, sizeof idx, "%lu", (unsigned long)i);
             r.put(std::string("iface.") + idx + ".name",
                   v[i].pInterfaceName ? (const char*)v[i].pInterfaceName : "<null>");
             r.num(std::string("iface.") + idx + ".flags", v[i].flags);
             if (ver) r.put(std::string("iface.") + idx + ".version",
                            std::to_string(ver->major) + "." + std::to_string(ver->minor));
         }
     }});

add({"env.profile_objects", "env",
     "CKO_PROFILE objects discoverable by C_FindObjects (Profiles v3.2 condition 4)",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_OBJECT_CLASS cl = CKO_PROFILE;
         CK_ATTRIBUTE t[] = { ATTR(CKA_CLASS, &cl, sizeof cl) };
         r.rv("find_init", e.fl->C_FindObjectsInit(s, t, 1));
         CK_OBJECT_HANDLE hs[16]; CK_ULONG n = 0;
         r.rv("find", e.fl->C_FindObjects(s, hs, 16, &n));
         r.num("count", n);
         std::vector<CK_ULONG> ids;
         for (CK_ULONG i = 0; i < n; i++) {
             CK_ULONG pid = 0;
             CK_ATTRIBUTE a = ATTR(CKA_PROFILE_ID, &pid, sizeof pid);
             if (e.fl->C_GetAttributeValue(s, hs[i], &a, 1) == CKR_OK) ids.push_back(pid);
         }
         std::sort(ids.begin(), ids.end());
         std::string j;
         for (size_t i = 0; i < ids.size(); i++) { if (i) j += ","; j += std::to_string(ids[i]); }
         r.put("profile_ids", j);
         e.fl->C_FindObjectsFinal(s);
     }});

// ---------------------------------------------------------------------------
// create — the attribute set after every object-creation path.
// This is coverage priority #1: the audit's defects clustered here.
// ---------------------------------------------------------------------------
add({"create.generate_key.aes256", "create",
     "C_GenerateKey CKM_AES_KEY_GEN — full attribute set of the produced key",
     {CKM_AES_KEY_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,   &len32,    sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_LABEL,       kLabel,    sizeof kLabel - 1),
             ATTR(CKA_ID,          kId,       sizeof kId),
             ATTR(CKA_ENCRYPT,     &bTrue,    sizeof bTrue),
             ATTR(CKA_DECRYPT,     &bTrue,    sizeof bTrue),
             ATTR(CKA_WRAP,        &bTrue,    sizeof bTrue),
             ATTR(CKA_UNWRAP,      &bTrue,    sizeof bTrue),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
         };
         gen_key(e, r, s, "gen", CKM_AES_KEY_GEN, t, sizeof t / sizeof t[0]);
     }});

add({"create.generate_key.generic_secret", "create",
     "C_GenerateKey CKM_GENERIC_SECRET_KEY_GEN — attribute set incl. CKA_CHECK_VALUE (§4.11)",
     {CKM_GENERIC_SECRET_KEY_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_VALUE_LEN,   &len32,     sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_LABEL,       kLabel,     sizeof kLabel - 1),
             ATTR(CKA_DERIVE,      &bTrue,     sizeof bTrue),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_VERIFY,      &bTrue,     sizeof bTrue),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
         };
         gen_key(e, r, s, "gen", CKM_GENERIC_SECRET_KEY_GEN, t, sizeof t / sizeof t[0]);
     }});

add({"create.generate_key_pair.ec_p256", "create",
     "EC P-256 key pair — CKA_EC_PARAMS/CKA_EC_POINT presence and encoding (E2, E4)",
     {CKM_EC_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_LABEL,     kLabel,    sizeof kLabel - 1),
             ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_LABEL,     kLabel,     sizeof kLabel - 1),
             ATTR(CKA_SIGN,      &bTrue,     sizeof bTrue),
             ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_EC_KEY_PAIR_GEN, pub, 6, priv, 7);
     }});

add({"create.generate_key_pair.ed25519", "create",
     "Ed25519 key pair — CKA_EC_POINT must be the bare 32 RFC 8032 bytes (E4)",
     {CKM_EC_EDWARDS_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic,   sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEdwards,  sizeof ktEdwards),
             ATTR(CKA_EC_PARAMS, kOidEd25519, sizeof kOidEd25519),
             ATTR(CKA_TOKEN,     &bFalse,     sizeof bFalse),
             ATTR(CKA_VERIFY,    &bTrue,      sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,     &clPrivate,  sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktEdwards,  sizeof ktEdwards),
             ATTR(CKA_TOKEN,     &bFalse,     sizeof bFalse),
             ATTR(CKA_SIGN,      &bTrue,      sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bTrue,      sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_EC_EDWARDS_KEY_PAIR_GEN, pub, 5, priv, 5);
     }});

add({"create.generate_key_pair.x25519", "create",
     "X25519 key pair — CKA_EC_POINT must be the bare 32 RFC 7748 bytes (E4)",
     {CKM_EC_MONTGOMERY_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic,  sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktMont,    sizeof ktMont),
             ATTR(CKA_EC_PARAMS, kOidX25519, sizeof kOidX25519),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktMont,    sizeof ktMont),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_EC_MONTGOMERY_KEY_PAIR_GEN, pub, 5, priv, 5);
     }});

add({"create.generate_key_pair.rsa2048", "create",
     "RSA-2048 key pair — the eight named private attributes (E5)",
     {CKM_RSA_PKCS_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ULONG bits = 2048;
         CK_BYTE  pe[] = {0x01, 0x00, 0x01};
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,           &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,        &ktRsa,    sizeof ktRsa),
             ATTR(CKA_MODULUS_BITS,    &bits,     sizeof bits),
             ATTR(CKA_PUBLIC_EXPONENT, pe,        sizeof pe),
             ATTR(CKA_TOKEN,           &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,          &bTrue,    sizeof bTrue),
             ATTR(CKA_ENCRYPT,         &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,    &ktRsa,     sizeof ktRsa),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_DECRYPT,     &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_RSA_PKCS_KEY_PAIR_GEN, pub, 7, priv, 7);
     }});

add({"create.generate_key_pair.ml_dsa_44", "create",
     "ML-DSA-44 key pair — private CKA_VALUE must be raw FIPS 204 bytes, not PKCS#8 (E3)",
     {CKM_ML_DSA_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &ktMlDsa,  sizeof ktMlDsa),
             ATTR(CKA_PARAMETER_SET, &psMlDsa44, sizeof psMlDsa44),
             ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &ktMlDsa,   sizeof ktMlDsa),
             ATTR(CKA_PARAMETER_SET, &psMlDsa44, sizeof psMlDsa44),
             ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,     &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE,   &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_ML_DSA_KEY_PAIR_GEN, pub, 5, priv, 7);
     }});

add({"create.generate_key_pair.ml_kem_768", "create",
     "ML-KEM-768 key pair — decapsulation key must be raw FIPS 203 bytes (E3)",
     {CKM_ML_KEM_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic,   sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &ktMlKem,    sizeof ktMlKem),
             ATTR(CKA_PARAMETER_SET, &psMlKem768, sizeof psMlKem768),
             ATTR(CKA_TOKEN,         &bFalse,     sizeof bFalse),
             ATTR(CKA_ENCAPSULATE,   &bTrue,      sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate,  sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &ktMlKem,    sizeof ktMlKem),
             ATTR(CKA_PARAMETER_SET, &psMlKem768, sizeof psMlKem768),
             ATTR(CKA_TOKEN,         &bFalse,     sizeof bFalse),
             ATTR(CKA_DECAPSULATE,   &bTrue,      sizeof bTrue),
             ATTR(CKA_SENSITIVE,     &bFalse,     sizeof bFalse),
             ATTR(CKA_EXTRACTABLE,   &bTrue,      sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_ML_KEM_KEY_PAIR_GEN, pub, 5, priv, 7);
     }});

add({"create.generate_key_pair.slh_dsa", "create",
     "SLH-DSA-SHA2-128s key pair — CKA_SEED must NOT be present (E7; §6.69.4 defines none)",
     {CKM_SLH_DSA_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x0000004bUL; // CKK_SLH_DSA
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &kt,       sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psSlhSha2128s, sizeof psSlhSha2128s),
             ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &kt,        sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psSlhSha2128s, sizeof psSlhSha2128s),
             ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_SLH_DSA_KEY_PAIR_GEN, pub, 5, priv, 5);
     }});

add({"create.generate_key_pair.xmss", "create",
     "XMSS key pair — S5: sensitive MUST be true and extractable MUST be false (§6.66.4)",
     {CKM_XMSS_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x00000047UL; // CKK_XMSS (pkcs11t.h)
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &kt,       sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psXmssSha2_10_256, sizeof psXmssSha2_10_256),
             ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &kt,        sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psXmssSha2_10_256, sizeof psXmssSha2_10_256),
             ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_XMSS_KEY_PAIR_GEN, pub, 5, priv, 5);
     }});

add({"create.generate_key_pair.xmssmt", "create",
     "XMSS^MT key pair — HBS-1: sensitive MUST be true, extractable and "
     "copyable MUST be false (§6.66.5; copyable is this engine's own "
     "extension of the identical HSS/XMSS one-time-signature hazard)",
     {CKM_XMSSMT_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x00000048UL; // CKK_XMSSMT (pkcs11t.h)
         static CK_ULONG psXmssMtSha2_20_2_256 = 1; // CKP_XMSSMT_SHA2_20_2_256
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &kt,       sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psXmssMtSha2_20_2_256, sizeof psXmssMtSha2_20_2_256),
             ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &kt,        sizeof kt),
             ATTR(CKA_PARAMETER_SET, &psXmssMtSha2_20_2_256, sizeof psXmssMtSha2_20_2_256),
             ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
         };
         // The smallest available parameter set (height 20, 2 layers) still
         // costs on the order of a minute per engine to generate — accepted
         // deliberately (2026-09-03) so CKA_COPYABLE gets checked on this
         // type too, not skipped for being the expensive one.
         gen_pair(e, r, s, "gen", CKM_XMSSMT_KEY_PAIR_GEN, pub, 5, priv, 5);
     }});

add({"create.generate_key_pair.hss", "create",
     "HSS key pair, default (no CK_HSS_KEY_PAIR_GEN_PARAMS) — HBS-1: "
     "sensitive MUST be true, extractable and copyable MUST be false "
     "(§6.65.3). No scenario exercised CKM_HSS_KEY_PAIR_GEN at all before "
     "this: the pre-fix divergence (C++ copyable=FALSE, Rust copyable=TRUE) "
     "was invisible to this harness for lack of a probe, not because the "
     "check itself was broken. Also pins down the LMOTS default both "
     "engines now share (W4) after HBS-1 aligned them.",
     {CKM_HSS_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x00000046UL; // CKK_HSS (pkcs11t.h)
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,    &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE, &kt,       sizeof kt),
             ATTR(CKA_TOKEN,    &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,   &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,    &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE, &kt,        sizeof kt),
             ATTR(CKA_TOKEN,    &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,     &bTrue,     sizeof bTrue),
         };
         gen_pair(e, r, s, "gen", CKM_HSS_KEY_PAIR_GEN, pub, 4, priv, 4);
     }});

add({"create.create_object.aes_secret", "create",
     "C_CreateObject of a secret key from a fixed value — the imported attribute set",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_RV rv = CKR_OK;
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE h = make_fixed_aes(e, s, true, &sens, &rv);
         r.rv("create", rv);
         record_attrs(e, r, "obj", s, h);
     }});

add({"create.create_object.data", "create",
     "C_CreateObject of a CKO_DATA object — the common attribute set",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BYTE payload[] = {0xde, 0xad, 0xbe, 0xef};
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clData, sizeof clData),
             ATTR(CKA_TOKEN,       &bFalse, sizeof bFalse),
             ATTR(CKA_PRIVATE,     &bFalse, sizeof bFalse),
             ATTR(CKA_LABEL,       kLabel,  sizeof kLabel - 1),
             ATTR(CKA_VALUE,       payload, sizeof payload),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("create", e.fl->C_CreateObject(s, t, 5, &h));
         record_attrs(e, r, "obj", s, h);
     }});

add({"create.derive.ecdh1_p256", "create",
     "C_DeriveKey CKM_ECDH1_DERIVE — attribute set of the derived secret",
     {CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bFalse,    sizeof bFalse),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;

         CK_ATTRIBUTE a = { CKA_EC_POINT, NULL_PTR, 0 };
         if (e.fl->C_GetAttributeValue(s, hPub, &a, 1) != CKR_OK) { r.put("peer_point", "UNREADABLE"); return; }
         std::vector<CK_BYTE> pt(a.ulValueLen); a.pValue = pt.data();
         e.fl->C_GetAttributeValue(s, hPub, &a, 1);
         r.put("peer_point.enc", classify(pt.data(), pt.size()));
         r.num("peer_point.len", pt.size());

         CK_ECDH1_DERIVE_PARAMS p;
         memset(&p, 0, sizeof p);
         p.kdf = CKD_NULL; p.pPublicData = pt.data(); p.ulPublicDataLen = (CK_ULONG)pt.size();
         CK_MECHANISM dm = { CKM_ECDH1_DERIVE, &p, sizeof p };
         CK_ATTRIBUTE dt[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_VALUE_LEN,   &len32,     sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
         };
         CK_OBJECT_HANDLE hd = CK_INVALID_HANDLE;
         r.rv("derive", e.fl->C_DeriveKey(s, &dm, hPriv, dt, 6, &hd));
         record_attrs(e, r, "derived", s, hd);
     }});

add({"create.unwrap.aes_kw", "create",
     "C_UnwrapKey under CKM_AES_KEY_WRAP — attribute set of the unwrapped key",
     {CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &sens);
         if (kek == CK_INVALID_HANDLE) { r.put("kek", "CREATE_FAILED"); return; }
         // Target key is also fixed, so the wrapped bytes are deterministic and
         // MUST be byte-identical across engines.
         CK_BYTE target[32]; for (int i = 0; i < 32; i++) target[i] = (CK_BYTE)(0x40 + i);
         CK_ATTRIBUTE tt[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_VALUE,       target,    sizeof target),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
             ATTR(CKA_ENCRYPT,     &bTrue,    sizeof bTrue),
         };
         CK_OBJECT_HANDLE ht = CK_INVALID_HANDLE;
         r.rv("create_target", e.fl->C_CreateObject(s, tt, 7, &ht));
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
         CK_BYTE wrapped[128]; CK_ULONG wlen = sizeof wrapped;
         CK_RV rv = e.fl->C_WrapKey(s, &wm, kek, ht, wrapped, &wlen);
         r.rv("wrap", rv);
         if (rv == CKR_OK) record_bytes(r, "wrapped", wrapped, wlen, ByteView::BYTES);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE ut[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
             ATTR(CKA_DECRYPT,     &bTrue,    sizeof bTrue),
         };
         CK_OBJECT_HANDLE hu = CK_INVALID_HANDLE;
         r.rv("unwrap", e.fl->C_UnwrapKey(s, &wm, kek, wrapped, wlen, ut, 6, &hu));
         record_attrs(e, r, "unwrapped", s, hu);
     }});

add({"create.encapsulate.ml_kem_768", "create",
     "C_EncapsulateKey / C_DecapsulateKey ML-KEM-768 — ciphertext shape and both key attribute sets",
     {CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         if (!e.Encapsulate || !e.Decapsulate) { r.put("fn", "ABSENT"); return; }
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,         &clPublic,   sizeof clPublic),
             ATTR(CKA_KEY_TYPE,      &ktMlKem,    sizeof ktMlKem),
             ATTR(CKA_PARAMETER_SET, &psMlKem768, sizeof psMlKem768),
             ATTR(CKA_TOKEN,         &bFalse,     sizeof bFalse),
             ATTR(CKA_ENCAPSULATE,   &bTrue,      sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,         &clPrivate,  sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,      &ktMlKem,    sizeof ktMlKem),
             ATTR(CKA_PARAMETER_SET, &psMlKem768, sizeof psMlKem768),
             ATTR(CKA_TOKEN,         &bFalse,     sizeof bFalse),
             ATTR(CKA_DECAPSULATE,   &bTrue,      sizeof bTrue),
         };
         CK_MECHANISM km = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE st[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_VALUE_LEN,   &len32,     sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
         };
         CK_MECHANISM em = { CKM_ML_KEM, NULL_PTR, 0 };
         CK_BYTE ct[4096]; CK_ULONG ctLen = sizeof ct;
         CK_OBJECT_HANDLE hEnc = CK_INVALID_HANDLE, hDec = CK_INVALID_HANDLE;
         rv = e.Encapsulate(s, &em, hPub, st, 6, ct, &ctLen, &hEnc);
         r.rv("encapsulate", rv);
         if (rv == CKR_OK) record_bytes(r, "ciphertext", ct, ctLen, ByteView::LEN);
         record_attrs(e, r, "encap_key", s, hEnc);
         if (rv != CKR_OK) return;
         rv = e.Decapsulate(s, &em, hPriv, st, 6, ct, ctLen, &hDec);
         r.rv("decapsulate", rv);
         record_attrs(e, r, "decap_key", s, hDec);
         // The two secrets must agree — checked inside each engine, so the
         // comparison across engines is of the VERDICT, not the bytes.
         auto val = [&](CK_OBJECT_HANDLE h, std::vector<CK_BYTE>& out) {
             CK_ATTRIBUTE a = { CKA_VALUE, NULL_PTR, 0 };
             if (e.fl->C_GetAttributeValue(s, h, &a, 1) != CKR_OK || a.ulValueLen == (CK_ULONG)-1) return false;
             out.resize(a.ulValueLen); a.pValue = out.data();
             return e.fl->C_GetAttributeValue(s, h, &a, 1) == CKR_OK;
         };
         std::vector<CK_BYTE> v1, v2;
         bool ok = val(hEnc, v1) && val(hDec, v2) && !v1.empty() && v1 == v2;
         r.put("shared_secret_agrees", ok ? "yes" : "no");
     }});

add({"create.encapsulate.ecdh_p256", "create",
     "ECDH-as-KEM (§6.3.17) — the ciphertext MUST be the raw 65-byte ephemeral point (E1)",
     {CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         if (!e.Encapsulate || !e.Decapsulate) { r.put("fn", "ABSENT"); return; }
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bFalse,    sizeof bFalse),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE st[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
         };
         CK_ECDH1_DERIVE_PARAMS p; memset(&p, 0, sizeof p); p.kdf = CKD_NULL;
         CK_MECHANISM em = { CKM_ECDH1_DERIVE, &p, sizeof p };
         CK_BYTE ct[512]; CK_ULONG ctLen = sizeof ct;
         CK_OBJECT_HANDLE hEnc = CK_INVALID_HANDLE, hDec = CK_INVALID_HANDLE;
         rv = e.Encapsulate(s, &em, hPub, st, 5, ct, &ctLen, &hEnc);
         r.rv("encapsulate", rv);
         if (rv == CKR_OK) record_bytes(r, "ciphertext", ct, ctLen, ByteView::SHAPE);
         record_attrs(e, r, "encap_key", s, hEnc);
         if (rv != CKR_OK) return;
         rv = e.Decapsulate(s, &em, hPriv, st, 5, ct, ctLen, &hDec);
         r.rv("decapsulate", rv);
         record_attrs(e, r, "decap_key", s, hDec);
     }});

// ---------------------------------------------------------------------------
// encoding — Phase 3, the bytes the specification names
// ---------------------------------------------------------------------------
add({"encoding.wrap_private_key_pkcs8", "encoding",
     "§6.7: a wrapped private key is BER-encoded PKCS#8 PrivateKeyInfo (E6)",
     {CKM_EC_KEY_PAIR_GEN, CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP_PAD}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &sens);
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,    &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 6, &hPub, &hPriv);
         r.rv("keygen", rv);
         if (rv != CKR_OK || kek == CK_INVALID_HANDLE) return;
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
         CK_BYTE out[4096]; CK_ULONG olen = sizeof out;
         rv = e.fl->C_WrapKey(s, &wm, kek, hPriv, out, &olen);
         r.rv("wrap_private", rv);
         if (rv != CKR_OK) return;
         // The wrapped blob is AES-KW ciphertext; its plaintext must be PKCS#8.
         // The only observable that survives encryption is the length, which
         // still distinguishes a PKCS#8 wrapper from a raw scalar. Recorded as
         // length-mod-8 plus a class so a change is visible.
         r.num("wrapped.len", olen);
         r.num("wrapped.len_mod8", olen % 8);
         // Round-trip it back to confirm the format is self-describing.
         CK_ATTRIBUTE ut[] = {
             ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,  &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,      &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bFalse,    sizeof bFalse),
         };
         CK_OBJECT_HANDLE hu = CK_INVALID_HANDLE;
         r.rv("unwrap_private", e.fl->C_UnwrapKey(s, &wm, kek, out, olen, ut, 5, &hu));
         record_attrs(e, r, "unwrapped_priv", s, hu);
     }});

// ---------------------------------------------------------------------------
// bytes — deterministic outputs. Fixed key + fixed IV + fixed plaintext, so
// any difference at all is a real difference.
// ---------------------------------------------------------------------------
static auto digest_case = [](CK_MECHANISM_TYPE mech) {
    return [mech](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
        CK_MECHANISM m = { mech, NULL_PTR, 0 };
        r.rv("digest_init", e.fl->C_DigestInit(s, &m));
        CK_BYTE out[128]; CK_ULONG olen = sizeof out;
        CK_RV rv = e.fl->C_Digest(s, kPlain32, sizeof kPlain32, out, &olen);
        r.rv("digest", rv);
        if (rv == CKR_OK) record_bytes(r, "out", out, olen, ByteView::BYTES);
    };
};

add({"bytes.digest_sha256", "bytes", "CKM_SHA256 over a fixed input — byte-identical",
     {CKM_SHA256}, true, true, digest_case(CKM_SHA256)});
add({"bytes.digest_sha3_256", "bytes", "CKM_SHA3_256 over a fixed input — byte-identical",
     {CKM_SHA3_256}, true, true, digest_case(CKM_SHA3_256)});

add({"bytes.hmac_sha256", "bytes", "CKM_SHA256_HMAC under a fixed key — byte-identical",
     {CKM_SHA256_HMAC}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_VALUE,       kFixedAes,  sizeof kFixedAes),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_VERIFY,      &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_CreateObject(s, t, 8, &h);
         r.rv("create_key", rv);
         if (rv != CKR_OK) return;
         CK_MECHANISM m = { CKM_SHA256_HMAC, NULL_PTR, 0 };
         r.rv("sign_init", e.fl->C_SignInit(s, &m, h));
         CK_BYTE out[64]; CK_ULONG olen = sizeof out;
         rv = e.fl->C_Sign(s, kPlain32, sizeof kPlain32, out, &olen);
         r.rv("sign", rv);
         if (rv == CKR_OK) record_bytes(r, "mac", out, olen, ByteView::BYTES);
     }});

static auto aes_case = [](CK_MECHANISM_TYPE mech, bool needs_iv) {
    return [mech, needs_iv](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
        CK_BBOOL sens = CK_FALSE;
        CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
        if (k == CK_INVALID_HANDLE) { r.put("key", "CREATE_FAILED"); return; }
        CK_MECHANISM m = { mech, needs_iv ? (CK_VOID_PTR)kFixedIv : NULL_PTR,
                           needs_iv ? (CK_ULONG)sizeof kFixedIv : 0 };
        r.rv("encrypt_init", e.fl->C_EncryptInit(s, &m, k));
        CK_BYTE out[256]; CK_ULONG olen = sizeof out;
        CK_RV rv = e.fl->C_Encrypt(s, kPlain32, sizeof kPlain32, out, &olen);
        r.rv("encrypt", rv);
        if (rv != CKR_OK) return;
        record_bytes(r, "ct", out, olen, ByteView::BYTES);
        r.rv("decrypt_init", e.fl->C_DecryptInit(s, &m, k));
        CK_BYTE back[256]; CK_ULONG blen = sizeof back;
        rv = e.fl->C_Decrypt(s, out, olen, back, &blen);
        r.rv("decrypt", rv);
        if (rv == CKR_OK) record_bytes(r, "pt", back, blen, ByteView::BYTES);
    };
};

add({"bytes.aes_ecb", "bytes", "CKM_AES_ECB, fixed key + fixed plaintext — byte-identical",
     {CKM_AES_ECB}, true, true, aes_case(CKM_AES_ECB, false)});
add({"bytes.aes_cbc", "bytes", "CKM_AES_CBC, fixed key + fixed IV — byte-identical",
     {CKM_AES_CBC}, true, true, aes_case(CKM_AES_CBC, true)});
add({"bytes.aes_ctr", "bytes", "CKM_AES_CTR with an explicit 128-bit counter block",
     {CKM_AES_CTR}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
         if (k == CK_INVALID_HANDLE) { r.put("key", "CREATE_FAILED"); return; }
         // Both counter widths, because a mismatch at one width and not the
         // other says which end of the parameter is being misread.
         for (CK_ULONG bits : {(CK_ULONG)128, (CK_ULONG)32}) {
             CK_AES_CTR_PARAMS p; memset(&p, 0, sizeof p);
             p.ulCounterBits = bits;
             memcpy(p.cb, kFixedIv, 16);
             CK_MECHANISM m = { CKM_AES_CTR, &p, sizeof p };
             std::string tag = "cb" + std::to_string(bits);
             r.rv(tag + ".encrypt_init", e.fl->C_EncryptInit(s, &m, k));
             CK_BYTE out[128]; CK_ULONG olen = sizeof out;
             CK_RV rv = e.fl->C_Encrypt(s, kPlain32, sizeof kPlain32, out, &olen);
             r.rv(tag + ".encrypt", rv);
             if (rv == CKR_OK) record_bytes(r, tag + ".ct", out, olen, ByteView::BYTES);
             else e.fl->C_EncryptInit(s, NULL_PTR, 0);
         }
     }});

// The scenario above compares the two engines to EACH OTHER, which cannot tell
// "both right" from "both wrong the same way". This one compares each engine to
// the published vector and records the verdict, so a shared defect is visible
// in the report even when the engines agree.
add({"bytes.aes_ctr_nist_kat", "bytes",
     "CKM_AES_CTR vs NIST SP 800-38A F.5.1/F.5.5 — the published vector, not the other engine",
     {CKM_AES_CTR}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         // SP 800-38A Appendix F block set — same plaintext for both vectors.
         static const CK_BYTE kNistPt[64] = {
             0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
             0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
             0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
         static const CK_BYTE kNistCb[16] = {
             0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
         static const CK_BYTE kKey128[16] = {
             0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
         static const CK_BYTE kCt128[64] = {
             0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
             0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
             0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
             0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};
         static const CK_BYTE kKey256[32] = {
             0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
             0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
         static const CK_BYTE kCt256[64] = {
             0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
             0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
             0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
             0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6};

         struct Vec { const char* name; const CK_BYTE* key; CK_ULONG klen; const CK_BYTE* ct; };
         const Vec vecs[] = {
             {"f551_aes128", kKey128, sizeof kKey128, kCt128},
             {"f555_aes256", kKey256, sizeof kKey256, kCt256},
         };
         for (const Vec& v : vecs) {
             CK_ATTRIBUTE t[] = {
                 ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
                 ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
                 ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
                 ATTR(CKA_VALUE,       (CK_VOID_PTR)v.key, v.klen),
                 ATTR(CKA_ENCRYPT,     &bTrue,    sizeof bTrue),
                 ATTR(CKA_DECRYPT,     &bTrue,    sizeof bTrue),
                 ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
                 ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
             };
             CK_OBJECT_HANDLE k = CK_INVALID_HANDLE;
             CK_RV crv = e.fl->C_CreateObject(s, t, sizeof t / sizeof t[0], &k);
             r.rv(std::string(v.name) + ".create_key", crv);
             if (crv != CKR_OK) continue;

             CK_AES_CTR_PARAMS p; memset(&p, 0, sizeof p);
             p.ulCounterBits = 128;
             memcpy(p.cb, kNistCb, 16);
             CK_MECHANISM m = { CKM_AES_CTR, &p, sizeof p };
             r.rv(std::string(v.name) + ".encrypt_init", e.fl->C_EncryptInit(s, &m, k));
             CK_BYTE out[128]; CK_ULONG olen = sizeof out;
             CK_RV rv = e.fl->C_Encrypt(s, (CK_BYTE_PTR)kNistPt, sizeof kNistPt, out, &olen);
             r.rv(std::string(v.name) + ".encrypt", rv);
             if (rv != CKR_OK) { e.fl->C_EncryptInit(s, NULL_PTR, 0); continue; }
             record_bytes(r, std::string(v.name) + ".ct", out, olen, ByteView::BYTES);
             // The verdict against the PUBLISHED vector. Recorded as its own
             // observation so it is diffed like everything else — and so the
             // report shows it even when both engines say the same thing.
             bool ok = (olen == sizeof kNistPt) && (memcmp(out, v.ct, sizeof kNistPt) == 0);
             r.put(std::string(v.name) + ".vs_nist_sp800_38a", ok ? "MATCH" : "MISMATCH");
         }
     }});

add({"bytes.aes_gcm", "bytes", "CKM_AES_GCM, fixed key + fixed nonce + fixed AAD — byte-identical",
     {CKM_AES_GCM}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
         if (k == CK_INVALID_HANDLE) { r.put("key", "CREATE_FAILED"); return; }
         CK_BYTE nonce[12]; memcpy(nonce, kFixedIv, 12);
         CK_BYTE aad[4] = {'d','i','f','f'};
         CK_GCM_PARAMS p; memset(&p, 0, sizeof p);
         p.pIv = nonce; p.ulIvLen = 12; p.ulIvBits = 96;
         p.pAAD = aad;  p.ulAADLen = sizeof aad;
         p.ulTagBits = 128;
         CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof p };
         r.rv("encrypt_init", e.fl->C_EncryptInit(s, &m, k));
         CK_BYTE out[128]; CK_ULONG olen = sizeof out;
         CK_RV rv = e.fl->C_Encrypt(s, kPlain32, sizeof kPlain32, out, &olen);
         r.rv("encrypt", rv);
         if (rv == CKR_OK) record_bytes(r, "ct", out, olen, ByteView::BYTES);
     }});

add({"bytes.aes_kw_wrap", "bytes",
     "CKM_AES_KEY_WRAP of a fixed key under a fixed KEK — the wrapped-key format, byte for byte",
     {CKM_AES_KEY_WRAP}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &sens);
         CK_BYTE target[16]; for (int i = 0; i < 16; i++) target[i] = (CK_BYTE)(0x90 + i);
         CK_ATTRIBUTE tt[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_VALUE,       target,    sizeof target),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
         };
         CK_OBJECT_HANDLE ht = CK_INVALID_HANDLE;
         r.rv("create_target", e.fl->C_CreateObject(s, tt, 6, &ht));
         if (kek == CK_INVALID_HANDLE || ht == CK_INVALID_HANDLE) return;
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
         CK_BYTE out[128]; CK_ULONG olen = sizeof out;
         CK_RV rv = e.fl->C_WrapKey(s, &wm, kek, ht, out, &olen);
         r.rv("wrap", rv);
         if (rv == CKR_OK) record_bytes(r, "wrapped", out, olen, ByteView::BYTES);
     }});

// ---------------------------------------------------------------------------
// errors — Phase 4
// ---------------------------------------------------------------------------
add({"errors.bad_slot_ids", "errors",
     "Every slot-taking entry point must reject a nonexistent slot (W6)",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         const CK_SLOT_ID bad = 9999;
         CK_MECHANISM_INFO mi; CK_SLOT_INFO si; CK_TOKEN_INFO ti;
         r.rv("C_GetMechanismInfo", e.fl->C_GetMechanismInfo(bad, CKM_AES_CBC, &mi));
         r.rv("C_GetSlotInfo",      e.fl->C_GetSlotInfo(bad, &si));
         r.rv("C_GetTokenInfo",     e.fl->C_GetTokenInfo(bad, &ti));
         CK_ULONG n = 0;
         r.rv("C_GetMechanismList", e.fl->C_GetMechanismList(bad, NULL_PTR, &n));
         CK_SESSION_HANDLE s2 = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_OpenSession(bad, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s2);
         r.rv("C_OpenSession", rv);
         if (rv == CKR_OK) e.fl->C_CloseSession(s2);
     }});

add({"errors.session_handle_precedence", "errors",
     "The session-handle code takes mandatory precedence over argument/capability codes (C2)",
     {}, true, false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE) {
         const CK_SESSION_HANDLE bad = 0xdeadbeef;
         CK_SESSION_INFO si;
         r.rv("C_GetSessionInfo", e.fl->C_GetSessionInfo(bad, &si));
         // Bad handle AND a null mechanism: the handle must win.
         r.rv("C_SignInit_null_mech",    e.fl->C_SignInit(bad, NULL_PTR, 0));
         r.rv("C_EncryptInit_null_mech", e.fl->C_EncryptInit(bad, NULL_PTR, 0));
         r.rv("C_DigestInit_null_mech",  e.fl->C_DigestInit(bad, NULL_PTR));
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("C_GenerateKey_null_mech", e.fl->C_GenerateKey(bad, NULL_PTR, NULL_PTR, 0, &h));
         r.rv("C_FindObjectsInit_null",  e.fl->C_FindObjectsInit(bad, NULL_PTR, 0));
         r.rv("C_Logout",                e.fl->C_Logout(bad));
     }});

add({"errors.null_mechanism_cancel", "errors",
     "§5.x: a null mechanism cancels an active operation — success, or cancel-failed (C2)",
     {CKM_SHA256, CKM_AES_KEY_GEN, CKM_AES_CBC}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_MECHANISM dm = { CKM_SHA256, NULL_PTR, 0 };
         r.rv("digest_init",         e.fl->C_DigestInit(s, &dm));
         r.rv("digest_cancel",       e.fl->C_DigestInit(s, NULL_PTR));
         r.rv("digest_cancel_again", e.fl->C_DigestInit(s, NULL_PTR));
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
         if (k == CK_INVALID_HANDLE) return;
         CK_MECHANISM em = { CKM_AES_CBC, kFixedIv, sizeof kFixedIv };
         r.rv("encrypt_init",   e.fl->C_EncryptInit(s, &em, k));
         r.rv("encrypt_cancel", e.fl->C_EncryptInit(s, NULL_PTR, 0));
         r.rv("sign_cancel_when_idle", e.fl->C_SignInit(s, NULL_PTR, 0));
     }});

add({"errors.unsupported_curve", "errors",
     "W1/C2: an unimplemented curve must be curve-not-supported, never a silent P-256 key",
     {CKM_EC_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic,     sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,         sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidBrainpool, sizeof kOidBrainpool),
             ATTR(CKA_TOKEN,     &bFalse,       sizeof bFalse),
             ATTR(CKA_VERIFY,    &bTrue,        sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,    &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE, &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,    &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,     &bTrue,     sizeof bTrue),
         };
         CK_MECHANISM m = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &m, pub, 5, priv, 4, &hPub, &hPriv);
         r.rv("brainpool", rv);
         r.put("brainpool.outcome", rv == CKR_OK ? "key_produced" : "refused");
         if (rv == CKR_OK) {
             // If a key WAS produced, record which curve it actually is — the
             // W1 defect returned success and stamped it P-256.
             CK_ATTRIBUTE a = { CKA_EC_PARAMS, NULL_PTR, 0 };
             if (e.fl->C_GetAttributeValue(s, hPub, &a, 1) == CKR_OK && a.ulValueLen != (CK_ULONG)-1) {
                 std::vector<CK_BYTE> v(a.ulValueLen); a.pValue = v.data();
                 e.fl->C_GetAttributeValue(s, hPub, &a, 1);
                 r.put("brainpool.actual_ec_params", to_hex(v.data(), v.size()));
             }
         }
         // Missing CKA_EC_PARAMS entirely → template-incomplete.
         CK_ATTRIBUTE pub2[] = {
             ATTR(CKA_CLASS,    &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE, &ktEc,     sizeof ktEc),
             ATTR(CKA_TOKEN,    &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,   &bTrue,    sizeof bTrue),
         };
         hPub = hPriv = CK_INVALID_HANDLE;
         r.rv("missing_ec_params", e.fl->C_GenerateKeyPair(s, &m, pub2, 4, priv, 4, &hPub, &hPriv));
     }});

add({"errors.find_objects_arguments", "errors",
     "W5: a null template with a non-zero count must not silently widen to find-all",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         make_fixed_aes(e, s, true, &sens);
         CK_RV rv = e.fl->C_FindObjectsInit(s, NULL_PTR, 5);
         r.rv("find_init_null_template_count5", rv);
         if (rv == CKR_OK) {
             CK_OBJECT_HANDLE hs[64]; CK_ULONG n = 0;
             r.rv("find", e.fl->C_FindObjects(s, hs, 64, &n));
             r.put("find.returned_any", n ? "yes" : "no");
             e.fl->C_FindObjectsFinal(s);
         }
         r.rv("find_init_null_template_count0", e.fl->C_FindObjectsInit(s, NULL_PTR, 0));
         e.fl->C_FindObjectsFinal(s);
     }});

add({"errors.login_context_specific", "errors",
     "C2: context-specific is one of the three valid user types",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         r.rv("context_specific_no_pending",
              e.fl->C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN)));
         r.rv("bogus_user_type",
              e.fl->C_Login(s, 99, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN)));
     }});

add({"errors.create_profile_object", "errors",
     "C1: application creation of a CKO_PROFILE object must be refused",
     {}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_OBJECT_CLASS cl = CKO_PROFILE;
         CK_ULONG pid = CKP_BASELINE_PROVIDER;
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,      &cl,     sizeof cl),
             ATTR(CKA_PROFILE_ID, &pid,    sizeof pid),
             ATTR(CKA_TOKEN,      &bFalse, sizeof bFalse),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("create_profile", e.fl->C_CreateObject(s, t, 3, &h));
     }});

add({"errors.unwrap_garbage", "errors",
     "An unwrap of non-ciphertext must fail, and with a wrapped-key code",
     {CKM_AES_KEY_WRAP}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &sens);
         if (kek == CK_INVALID_HANDLE) return;
         CK_BYTE junk[24]; memset(junk, 0x5a, sizeof junk);
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
         CK_ATTRIBUTE ut[] = {
             ATTR(CKA_CLASS,    &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE, &ktAes,    sizeof ktAes),
             ATTR(CKA_TOKEN,    &bFalse,   sizeof bFalse),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("unwrap_junk", e.fl->C_UnwrapKey(s, &wm, kek, junk, sizeof junk, ut, 3, &h));
         CK_BYTE tooShort[4] = {1,2,3,4};
         r.rv("unwrap_short", e.fl->C_UnwrapKey(s, &wm, kek, tooShort, sizeof tooShort, ut, 3, &h));
     }});

// ---------------------------------------------------------------------------
// security — Phase 1, only the parts observable through the API
// ---------------------------------------------------------------------------
add({"security.copyable_one_way", "security",
     "S10: CKA_COPYABLE false→true must be refused, and copy must then fail",
     {CKM_AES_KEY_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,   &len32,    sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKey(s, &m, t, 6, &h);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE off = ATTR(CKA_COPYABLE, &bFalse, sizeof bFalse);
         r.rv("set_false", e.fl->C_SetAttributeValue(s, h, &off, 1));
         CK_ATTRIBUTE on = ATTR(CKA_COPYABLE, &bTrue, sizeof bTrue);
         r.rv("set_true_again", e.fl->C_SetAttributeValue(s, h, &on, 1));
         CK_OBJECT_HANDLE hc = CK_INVALID_HANDLE;
         r.rv("copy", e.fl->C_CopyObject(s, h, NULL_PTR, 0, &hc));
     }});

add({"security.wrap_with_trusted_one_way", "security",
     "S3-adjacent: CKA_WRAP_WITH_TRUSTED false→true, then a wrap under an untrusted key",
     {CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,             &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,          &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,         &len32,    sizeof len32),
             ATTR(CKA_TOKEN,             &bFalse,   sizeof bFalse),
             ATTR(CKA_EXTRACTABLE,       &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,         &bFalse,   sizeof bFalse),
             ATTR(CKA_WRAP_WITH_TRUSTED, &bTrue,    sizeof bTrue),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKey(s, &m, t, 7, &h);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         record_attrs(e, r, "key", s, h);
         CK_ATTRIBUTE clear = ATTR(CKA_WRAP_WITH_TRUSTED, &bFalse, sizeof bFalse);
         r.rv("clear_flag", e.fl->C_SetAttributeValue(s, h, &clear, 1));
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &sens);  // untrusted
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
         CK_BYTE out[128]; CK_ULONG olen = sizeof out;
         r.rv("wrap_under_untrusted", e.fl->C_WrapKey(s, &wm, kek, h, out, &olen));
     }});

add({"security.sensitive_value_hidden", "security",
     "A sensitive key's CKA_VALUE must answer with the sensitive code, not the bytes",
     {CKM_AES_KEY_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,   &len32,    sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_SENSITIVE,   &bTrue,    sizeof bTrue),
             ATTR(CKA_EXTRACTABLE, &bFalse,   sizeof bFalse),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKey(s, &m, t, 6, &h);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         record_attrs(e, r, "key", s, h);
         CK_ATTRIBUTE unset = ATTR(CKA_SENSITIVE, &bFalse, sizeof bFalse);
         r.rv("downgrade_sensitive", e.fl->C_SetAttributeValue(s, h, &unset, 1));
         CK_ATTRIBUTE ext = ATTR(CKA_EXTRACTABLE, &bTrue, sizeof bTrue);
         r.rv("upgrade_extractable", e.fl->C_SetAttributeValue(s, h, &ext, 1));
     }});

// WS-1.2 (2026-08-29) — CKA_VALUE sensitivity on ASYMMETRIC private keys.
//
// Why this exists: the only prior probe of the §4.9 note-7 rule
// (security.sensitive_value_hidden, just above) uses an AES secret key. The
// PKCS#11 v3.2 EC / Edwards private-key tables define CKA_VALUE too — it is
// the private scalar d, and it is exactly the material a sensitive key must
// never disclose — but nothing asserted the rule there, on either engine, for
// either a generated or an unwrapped key. That gap is what let
// DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS bundle a sensitivity claim in with
// its formatting claims without anyone being able to test the two apart.
//
// Four cases, each pinning one leg of the rule:
//   gen_sensitive     CKA_SENSITIVE=TRUE,  CKA_EXTRACTABLE=TRUE  (sensitive leg)
//   gen_unextractable CKA_SENSITIVE=FALSE, CKA_EXTRACTABLE=FALSE (extractable leg)
//   unwrapped_*       the same two, on a key that arrived via C_UnwrapKey
//
// The unwrap templates set BOTH attributes explicitly rather than relying on a
// default, deliberately: LEGAL-UNWRAPPED-KEY-EXTRACTABLE-DEFAULT already
// records that the two engines pick different CKA_EXTRACTABLE defaults for an
// unwrapped key, so a probe that left it unset would measure that adjudicated
// difference instead of the enforcement rule this scenario is about.
static auto probe_value_sensitivity = [](Engine& e, Recorder& r, CK_SESSION_HANDLE s,
                                         const std::string& tag, CK_OBJECT_HANDLE h) {
    if (h == CK_INVALID_HANDLE) return;
    CK_BYTE buf[4096];
    CK_ATTRIBUTE a = { CKA_VALUE, buf, sizeof buf };
    CK_RV rv = e.fl->C_GetAttributeValue(s, h, &a, 1);
    r.rv(tag + ".CKA_VALUE", rv);
    // A normalised verdict alongside the raw code: CKR_ATTRIBUTE_SENSITIVE and
    // CKR_ATTRIBUTE_TYPE_INVALID are both refusals, and which one an engine
    // picks depends on whether it materialises CKA_VALUE for this key type at
    // all — a separate question, already covered by its own exception entry.
    // What must never differ is whether the bytes came out.
    const char* verdict = (rv == CKR_OK && a.ulValueLen != (CK_ULONG)-1)
                        ? "DISCLOSED" : "REFUSED";
    r.put(tag + ".CKA_VALUE.disclosure", verdict);
};

add({"security.private_key_value_sensitivity", "security",
     "A sensitive or unextractable EC/Edwards private key must not disclose CKA_VALUE — generated or unwrapped (WS-1.2)",
     {CKM_EC_KEY_PAIR_GEN, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP_PAD}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         // ---- generated keys, both legs of the rule, both curve families ----
         struct Case { const char* tag; CK_BBOOL sens; CK_BBOOL extr; };
         const Case cases[] = {
             { "gen_sensitive",     CK_TRUE,  CK_TRUE  },
             { "gen_unextractable", CK_FALSE, CK_FALSE },
         };
         for (const auto& c : cases) {
             CK_BBOOL sens = c.sens, extr = c.extr;
             {
                 CK_ATTRIBUTE pub[] = {
                     ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
                     ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
                     ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
                     ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
                     ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
                 };
                 CK_ATTRIBUTE priv[] = {
                     ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
                     ATTR(CKA_KEY_TYPE,    &ktEc,      sizeof ktEc),
                     ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
                     ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
                     ATTR(CKA_SENSITIVE,   &sens,      sizeof sens),
                     ATTR(CKA_EXTRACTABLE, &extr,      sizeof extr),
                 };
                 CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
                 CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
                 std::string tag = std::string("ec.") + c.tag;
                 CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 6, &hPub, &hPriv);
                 r.rv(tag, rv);
                 if (rv == CKR_OK) probe_value_sensitivity(e, r, s, tag, hPriv);
             }
             {
                 CK_ATTRIBUTE pub[] = {
                     ATTR(CKA_CLASS,     &clPublic,   sizeof clPublic),
                     ATTR(CKA_KEY_TYPE,  &ktEdwards,  sizeof ktEdwards),
                     ATTR(CKA_EC_PARAMS, kOidEd25519, sizeof kOidEd25519),
                     ATTR(CKA_TOKEN,     &bFalse,     sizeof bFalse),
                     ATTR(CKA_VERIFY,    &bTrue,      sizeof bTrue),
                 };
                 CK_ATTRIBUTE priv[] = {
                     ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
                     ATTR(CKA_KEY_TYPE,    &ktEdwards, sizeof ktEdwards),
                     ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
                     ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
                     ATTR(CKA_SENSITIVE,   &sens,      sizeof sens),
                     ATTR(CKA_EXTRACTABLE, &extr,      sizeof extr),
                 };
                 CK_MECHANISM km = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
                 CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
                 std::string tag = std::string("ed25519.") + c.tag;
                 CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 6, &hPub, &hPriv);
                 r.rv(tag, rv);
                 if (rv == CKR_OK) probe_value_sensitivity(e, r, s, tag, hPriv);
             }
         }

         // ---- the same rule on a key that arrived through C_UnwrapKey ----
         // Wrap a deliberately non-sensitive, extractable P-256 private key
         // (the only kind that CAN be wrapped), then unwrap it back under
         // templates that DO assert the rule.
         CK_BBOOL kekSens = CK_FALSE;
         CK_OBJECT_HANDLE kek = make_fixed_aes(e, s, true, &kekSens);
         if (kek == CK_INVALID_HANDLE) return;
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,    &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 6, &hPub, &hPriv);
         r.rv("wrappable_keygen", rv);
         if (rv != CKR_OK) return;
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
         CK_BYTE out[4096]; CK_ULONG olen = sizeof out;
         rv = e.fl->C_WrapKey(s, &wm, kek, hPriv, out, &olen);
         r.rv("wrap_private", rv);
         if (rv != CKR_OK) return;
         for (const auto& c : cases) {
             CK_BBOOL sens = c.sens, extr = c.extr;
             CK_ATTRIBUTE ut[] = {
                 ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,    &ktEc,      sizeof ktEc),
                 ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
                 ATTR(CKA_SENSITIVE,   &sens,      sizeof sens),
                 ATTR(CKA_EXTRACTABLE, &extr,      sizeof extr),
             };
             CK_OBJECT_HANDLE hu = CK_INVALID_HANDLE;
             std::string tag = std::string("ec.unwrapped_") + (c.sens ? "sensitive" : "unextractable");
             CK_RV urv = e.fl->C_UnwrapKey(s, &wm, kek, out, olen, ut, 6, &hu);
             r.rv(tag, urv);
             if (urv == CKR_OK) probe_value_sensitivity(e, r, s, tag, hu);
         }
     }});

add({"security.allowed_mechanisms", "security",
     "S9: a key restricted to one mechanism must refuse every other one",
     {CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_ECB}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_MECHANISM_TYPE allowed[] = { CKM_AES_CBC };
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,              &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,           &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,          &len32,    sizeof len32),
             ATTR(CKA_TOKEN,              &bFalse,   sizeof bFalse),
             ATTR(CKA_ENCRYPT,            &bTrue,    sizeof bTrue),
             ATTR(CKA_DECRYPT,            &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,          &bFalse,   sizeof bFalse),
             ATTR(CKA_ALLOWED_MECHANISMS, allowed,   sizeof allowed),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKey(s, &m, t, 8, &h);
         r.rv("keygen", rv);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE a = { CKA_ALLOWED_MECHANISMS, NULL_PTR, 0 };
         if (e.fl->C_GetAttributeValue(s, h, &a, 1) == CKR_OK && a.ulValueLen != (CK_ULONG)-1) {
             r.num("stored.len", a.ulValueLen);
             r.num("stored.element_count_if_CK_ULONG", a.ulValueLen / sizeof(CK_ULONG));
         }
         CK_MECHANISM cbc = { CKM_AES_CBC, kFixedIv, sizeof kFixedIv };
         r.rv("cbc_permitted", e.fl->C_EncryptInit(s, &cbc, h));
         e.fl->C_EncryptInit(s, NULL_PTR, 0);
         CK_MECHANISM ecb = { CKM_AES_ECB, NULL_PTR, 0 };
         r.rv("ecb_refused", e.fl->C_EncryptInit(s, &ecb, h));
         e.fl->C_EncryptInit(s, NULL_PTR, 0);
         // Mechanism 0 is RSA key-pair generation; a fail-open width bug makes
         // an 8-byte-per-element list parse as {mech, 0, ...} and silently
         // permit it. Nothing in the template allowed it.
         CK_MECHANISM rsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
         r.rv("mech_zero_refused", e.fl->C_EncryptInit(s, &rsa, h));
         e.fl->C_EncryptInit(s, NULL_PTR, 0);
     }});

add({"security.readonly_session_refusals", "security",
     "S7: a read-only session may not create or destroy token objects",
     {CKM_AES_KEY_GEN, CKM_EC_KEY_PAIR_GEN}, /*rw*/false, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_SESSION_INFO si; memset(&si, 0, sizeof si);
         if (e.fl->C_GetSessionInfo(s, &si) == CKR_OK) r.num("session_state", si.state);
         CK_ATTRIBUTE tok[] = {
             ATTR(CKA_CLASS,     &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,  &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN, &len32,    sizeof len32),
             ATTR(CKA_TOKEN,     &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE, &bFalse,   sizeof bFalse),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("generate_key_token", e.fl->C_GenerateKey(s, &m, tok, 5, &h));
         r.put("generate_key_token.object_produced", h != CK_INVALID_HANDLE ? "yes" : "no");

         CK_ATTRIBUTE co[] = {
             ATTR(CKA_CLASS,   &clData, sizeof clData),
             ATTR(CKA_TOKEN,   &bTrue,  sizeof bTrue),
             ATTR(CKA_PRIVATE, &bFalse, sizeof bFalse),
             ATTR(CKA_LABEL,   kLabel,  sizeof kLabel - 1),
         };
         CK_OBJECT_HANDLE hd = CK_INVALID_HANDLE;
         r.rv("create_object_token", e.fl->C_CreateObject(s, co, 4, &hd));

         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bTrue,    sizeof bTrue),
             ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,    &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE, &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,    &bTrue,     sizeof bTrue),
             ATTR(CKA_SIGN,     &bTrue,     sizeof bTrue),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
         r.rv("generate_key_pair_token", e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 4, &hPub, &hPriv));

         // Session objects must STILL be creatable in a read-only session.
         CK_ATTRIBUTE sess[] = {
             ATTR(CKA_CLASS,     &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,  &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN, &len32,    sizeof len32),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_SENSITIVE, &bFalse,   sizeof bFalse),
         };
         CK_OBJECT_HANDLE hs = CK_INVALID_HANDLE;
         r.rv("generate_key_session", e.fl->C_GenerateKey(s, &m, sess, 5, &hs));
         if (hs != CK_INVALID_HANDLE) r.rv("destroy_session_object", e.fl->C_DestroyObject(s, hs));
     }});

add({"security.logout_invalidates_handles", "security",
     "S6/C6: logout invalidates private-object handles, and they stay invalid after re-login",
     {}, true, /*login handled inside*/false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_RV rv = e.fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
         r.rv("login", rv);
         if (rv != CKR_OK) return;
         CK_BYTE payload[] = {0x01, 0x02};
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,   &clData, sizeof clData),
             ATTR(CKA_TOKEN,   &bFalse, sizeof bFalse),
             ATTR(CKA_PRIVATE, &bTrue,  sizeof bTrue),
             ATTR(CKA_LABEL,   kLabel,  sizeof kLabel - 1),
             ATTR(CKA_VALUE,   payload, sizeof payload),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("create_private", e.fl->C_CreateObject(s, t, 5, &h));
         if (h == CK_INVALID_HANDLE) return;
         CK_ATTRIBUTE probe = { CKA_LABEL, NULL_PTR, 0 };
         r.rv("read_before_logout", e.fl->C_GetAttributeValue(s, h, &probe, 1));
         r.rv("logout", e.fl->C_Logout(s));
         r.rv("read_after_logout", e.fl->C_GetAttributeValue(s, h, &probe, 1));
         r.rv("relogin", e.fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN)));
         r.rv("read_after_relogin", e.fl->C_GetAttributeValue(s, h, &probe, 1));
     }});

add({"security.close_all_sessions_logs_out", "security",
     "§5.6.2/§5.6.3: after close-all-sessions a fresh session must be public, not pre-authenticated",
     {}, true, /*login handled inside*/false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         r.rv("login", e.fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN)));
         r.rv("close_all", e.fl->C_CloseAllSessions(e.slot));
         CK_SESSION_HANDLE s2 = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_OpenSession(e.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                        NULL_PTR, NULL_PTR, &s2);
         r.rv("reopen", rv);
         if (rv != CKR_OK) return;
         CK_SESSION_INFO si; memset(&si, 0, sizeof si);
         r.rv("session_info", e.fl->C_GetSessionInfo(s2, &si));
         r.num("state", si.state);
         r.put("state_is_public", (si.state == CKS_RW_PUBLIC_SESSION) ? "yes" : "no");
         e.fl->C_CloseSession(s2);
     }});

add({"security.so_cannot_see_private", "security",
     "S8: the security officer has no access to private objects (Usage Guide access matrix)",
     {}, true, /*login handled inside*/false,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         r.rv("user_login", e.fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN)));
         CK_BYTE payload[] = {0x07};
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,   &clData, sizeof clData),
             ATTR(CKA_TOKEN,   &bTrue,  sizeof bTrue),
             ATTR(CKA_PRIVATE, &bTrue,  sizeof bTrue),
             ATTR(CKA_LABEL,   kLabel,  sizeof kLabel - 1),
             ATTR(CKA_VALUE,   payload, sizeof payload),
         };
         CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
         r.rv("create_private_token_object", e.fl->C_CreateObject(s, t, 5, &h));
         r.rv("user_logout", e.fl->C_Logout(s));
         r.rv("so_login", e.fl->C_Login(s, CKU_SO, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN)));
         CK_OBJECT_CLASS cl = CKO_DATA;
         CK_ATTRIBUTE f[] = { ATTR(CKA_CLASS, &cl, sizeof cl) };
         r.rv("find_init_as_so", e.fl->C_FindObjectsInit(s, f, 1));
         CK_OBJECT_HANDLE hs[32]; CK_ULONG n = 0;
         r.rv("find_as_so", e.fl->C_FindObjects(s, hs, 32, &n));
         r.num("visible_to_so", n);
         e.fl->C_FindObjectsFinal(s);
         e.fl->C_Logout(s);
     }});

add({"security.wrap_template_partition", "security",
     "S2/§5.18.3: a wrap template mismatch SHALL return the invalid-handle code",
     {CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP, CKM_EC_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_OBJECT_CLASS want = CKO_SECRET_KEY;
         CK_ATTRIBUTE wt[] = { ATTR(CKA_CLASS, &want, sizeof want) };
         CK_ATTRIBUTE kt[] = {
             ATTR(CKA_CLASS,         &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,      &ktAes,    sizeof ktAes),
             ATTR(CKA_VALUE_LEN,     &len32,    sizeof len32),
             ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
             ATTR(CKA_WRAP,          &bTrue,    sizeof bTrue),
             ATTR(CKA_UNWRAP,        &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,     &bFalse,   sizeof bFalse),
             ATTR(CKA_WRAP_TEMPLATE, wt,        sizeof wt),
         };
         CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
         CK_RV rv = e.fl->C_GenerateKey(s, &m, kt, 8, &kek);
         r.rv("keygen_with_wrap_template", rv);
         if (rv != CKR_OK) return;
         CK_ATTRIBUTE a = { CKA_WRAP_TEMPLATE, NULL_PTR, 0 };
         r.rv("read_back_wrap_template", e.fl->C_GetAttributeValue(s, kek, &a, 1));

         // Positive: a secret key matches the template and must wrap.
         CK_BYTE tgt[16]; memset(tgt, 0x33, sizeof tgt);
         CK_ATTRIBUTE tt[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAes,    sizeof ktAes),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_VALUE,       tgt,       sizeof tgt),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
         };
         CK_OBJECT_HANDLE ht = CK_INVALID_HANDLE;
         e.fl->C_CreateObject(s, tt, 6, &ht);
         CK_MECHANISM wm = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
         CK_BYTE out[4096]; CK_ULONG olen = sizeof out;
         r.rv("wrap_matching_secret", e.fl->C_WrapKey(s, &wm, kek, ht, out, &olen));

         // Negative: a private key does not match and must be refused.
         CK_ATTRIBUTE pub[] = {
             ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
             ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
             ATTR(CKA_EC_PARAMS, kOidP256,  sizeof kOidP256),
             ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
             ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
         };
         CK_ATTRIBUTE priv[] = {
             ATTR(CKA_CLASS,       &clPrivate, sizeof clPrivate),
             ATTR(CKA_KEY_TYPE,    &ktEc,      sizeof ktEc),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_SIGN,        &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
         };
         CK_MECHANISM km = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
         CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
         if (e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 6, &hPub, &hPriv) == CKR_OK) {
             olen = sizeof out;
             r.rv("wrap_mismatching_private", e.fl->C_WrapKey(s, &wm, kek, hPriv, out, &olen));
         }
     }});

// ---------------------------------------------------------------------------
// bytes / create — WS-8 parity set (2026-08-30): AES-GMAC, AES-CCM, AES-XTS,
// AES-OFB/CFB128/CFB8/CFB1, and SP800-108 Double-Pipeline KDF landed on BOTH
// engines this session (C++ via WS-8, Rust via the matching remediation
// plan) but had never been run through this harness — added here rather
// than assumed compatible.
//
// CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS (FIPS 186-5 A.2.2) is Rust-only as of
// this writing — the C++ investigation was paused mid-implementation
// (spec text was still being read) and never actually wrote the mechanism.
// The scenario below is added anyway: the harness's mechanism gate turns
// that into a single legible "C++ unsupported" line per LEGAL-MECHANISM-SET
// rather than a crash, and the scenario is then already in place the day
// C++ catches up.
// ---------------------------------------------------------------------------

add({"bytes.aes_gmac", "bytes",
     "CKM_AES_GMAC, fixed key + fixed IV + fixed data — byte-identical tag",
     {CKM_AES_GMAC}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
         if (k == CK_INVALID_HANDLE) { r.put("key", "CREATE_FAILED"); return; }
         CK_BYTE iv[12]; memcpy(iv, kFixedIv, 12);
         CK_GCM_PARAMS p; memset(&p, 0, sizeof p);
         p.pIv = iv; p.ulIvLen = 12; p.ulIvBits = 96;
         p.ulTagBits = 128;
         CK_MECHANISM m = { CKM_AES_GMAC, &p, sizeof p };
         r.rv("sign_init", e.fl->C_SignInit(s, &m, k));
         CK_BYTE out[16]; CK_ULONG olen = sizeof out;
         CK_RV rv = e.fl->C_Sign(s, kPlain32, sizeof kPlain32, out, &olen);
         r.rv("sign", rv);
         if (rv == CKR_OK) record_bytes(r, "tag", out, olen, ByteView::BYTES);
     }});

add({"bytes.aes_ccm", "bytes",
     "CKM_AES_CCM, fixed key + fixed nonce + fixed AAD — byte-identical ciphertext+tag",
     {CKM_AES_CCM}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
         if (k == CK_INVALID_HANDLE) { r.put("key", "CREATE_FAILED"); return; }
         CK_BYTE nonce[13]; memcpy(nonce, kFixedIv, 13);
         CK_BYTE aad[4] = {'d','i','f','f'};
         CK_CCM_PARAMS p; memset(&p, 0, sizeof p);
         p.ulDataLen = sizeof kPlain32;
         p.pNonce = nonce; p.ulNonceLen = sizeof nonce;
         p.pAAD = aad; p.ulAADLen = sizeof aad;
         p.ulMACLen = 16;
         CK_MECHANISM m = { CKM_AES_CCM, &p, sizeof p };
         r.rv("encrypt_init", e.fl->C_EncryptInit(s, &m, k));
         CK_BYTE out[64]; CK_ULONG olen = sizeof out;
         CK_RV rv = e.fl->C_Encrypt(s, kPlain32, sizeof kPlain32, out, &olen);
         r.rv("encrypt", rv);
         if (rv == CKR_OK) record_bytes(r, "ct_and_tag", out, olen, ByteView::BYTES);
     }});

add({"bytes.aes_xts", "bytes",
     "CKM_AES_XTS, fixed double-length key + fixed tweak, non-block-aligned length — byte-identical incl. ciphertext stealing",
     {CKM_AES_XTS}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         static CK_KEY_TYPE ktAesXts = CKK_AES_XTS;
         static CK_BYTE kFixedXts[32] = {
             0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
             0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
         };
         CK_ATTRIBUTE t[] = {
             ATTR(CKA_CLASS,       &clSecret, sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktAesXts, sizeof ktAesXts),
             ATTR(CKA_TOKEN,       &bFalse,   sizeof bFalse),
             ATTR(CKA_VALUE,       kFixedXts, sizeof kFixedXts),
             ATTR(CKA_ENCRYPT,     &bTrue,    sizeof bTrue),
             ATTR(CKA_DECRYPT,     &bTrue,    sizeof bTrue),
             ATTR(CKA_EXTRACTABLE, &bTrue,    sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,   sizeof bFalse),
         };
         CK_OBJECT_HANDLE k = CK_INVALID_HANDLE;
         r.rv("create_key", e.fl->C_CreateObject(s, t, 8, &k));
         if (k == CK_INVALID_HANDLE) return;
         CK_BYTE tweak[16]; memcpy(tweak, kFixedIv, 16);
         CK_MECHANISM m = { CKM_AES_XTS, tweak, sizeof tweak };
         r.rv("encrypt_init", e.fl->C_EncryptInit(s, &m, k));
         // 20 bytes — not a multiple of the 16-byte block, so a real
         // cross-engine mismatch in ciphertext-stealing shows up here.
         CK_BYTE pt[20]; memcpy(pt, kPlain32, 20);
         CK_BYTE out[32]; CK_ULONG olen = sizeof out;
         CK_RV rv = e.fl->C_Encrypt(s, pt, sizeof pt, out, &olen);
         r.rv("encrypt", rv);
         if (rv == CKR_OK) record_bytes(r, "ct", out, olen, ByteView::BYTES);
     }});

add({"bytes.aes_stream_modes", "bytes",
     "CKM_AES_OFB/CFB128/CFB8/CFB1, fixed key+IV — byte-identical per mode",
     {CKM_AES_OFB, CKM_AES_CFB128, CKM_AES_CFB8, CKM_AES_CFB1}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_BBOOL sens = CK_FALSE;
         struct Mode { const char* name; CK_MECHANISM_TYPE mech; };
         const Mode modes[] = {
             {"ofb", CKM_AES_OFB}, {"cfb128", CKM_AES_CFB128},
             {"cfb8", CKM_AES_CFB8}, {"cfb1", CKM_AES_CFB1},
         };
         for (const Mode& md : modes) {
             CK_OBJECT_HANDLE k = make_fixed_aes(e, s, true, &sens);
             std::string tag = md.name;
             if (k == CK_INVALID_HANDLE) { r.put(tag + ".key", "CREATE_FAILED"); continue; }
             CK_BYTE iv[16]; memcpy(iv, kFixedIv, 16);
             CK_MECHANISM m = { md.mech, iv, sizeof iv };
             r.rv(tag + ".encrypt_init", e.fl->C_EncryptInit(s, &m, k));
             CK_BYTE out[64]; CK_ULONG olen = sizeof out;
             CK_RV rv = e.fl->C_Encrypt(s, kPlain32, sizeof kPlain32, out, &olen);
             r.rv(tag + ".encrypt", rv);
             if (rv == CKR_OK) record_bytes(r, tag + ".ct", out, olen, ByteView::BYTES);
             else e.fl->C_EncryptInit(s, NULL_PTR, 0);
         }
     }});

add({"bytes.sp800_108_double_pipeline", "bytes",
     "CKM_SP800_108_DOUBLE_PIPELINE_KDF, fixed base key + fixed fixed-data — byte-identical DKM",
     {CKM_SP800_108_DOUBLE_PIPELINE_KDF}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_ATTRIBUTE bt[] = {
             ATTR(CKA_CLASS,    &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE, &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_TOKEN,    &bFalse,    sizeof bFalse),
             ATTR(CKA_VALUE,    kFixedAes,  sizeof kFixedAes),
             ATTR(CKA_DERIVE,   &bTrue,     sizeof bTrue),
         };
         CK_OBJECT_HANDLE hBase = CK_INVALID_HANDLE;
         r.rv("create_base", e.fl->C_CreateObject(s, bt, 5, &hBase));
         if (hBase == CK_INVALID_HANDLE) return;

         // CK_SP800_108_COUNTER (== CK_SP800_108_OPTIONAL_COUNTER, 0x2), NOT
         // CK_SP800_108_ITERATION_VARIABLE (0x1) — found via this scenario's
         // first run: C++'s Double-Pipeline handler only recognises the
         // former (Table 199/200's "optional counter" for Feedback/Double-
         // Pipeline modes), silently skipping the latter (Counter mode's
         // REQUIRED-counter type) and falling back to a hardcoded 32-bit
         // width, while Rust treats both types as interchangeable. Using
         // the mode-correct constant makes both engines read the same
         // 8-bit width. Position is placed BEFORE fixed data (index 0) —
         // Rust honours literal order; C++ hardwires "after A(i)" for
         // Double-Pipeline unconditionally, so position is not actually
         // comparable here, only width and value are.
         CK_SP800_108_COUNTER_FORMAT cf; memset(&cf, 0, sizeof cf);
         cf.bLittleEndian = CK_FALSE; cf.ulWidthInBits = 8;
         CK_BYTE fixedData[4] = {'d','i','f','f'};
         CK_PRF_DATA_PARAM dps[2];
         dps[0].type = CK_SP800_108_COUNTER;
         dps[0].pValue = &cf; dps[0].ulValueLen = sizeof cf;
         dps[1].type = CK_SP800_108_BYTE_ARRAY;
         dps[1].pValue = fixedData; dps[1].ulValueLen = sizeof fixedData;

         CK_SP800_108_KDF_PARAMS p; memset(&p, 0, sizeof p);
         p.prfType = CKM_SHA256_HMAC;
         p.ulNumberOfDataParams = 2;
         p.pDataParams = dps;
         CK_MECHANISM m = { CKM_SP800_108_DOUBLE_PIPELINE_KDF, &p, sizeof p };

         CK_ATTRIBUTE dt[] = {
             ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
             ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
             ATTR(CKA_VALUE_LEN,   &len32,     sizeof len32),
             ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
             ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
             ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
         };
         CK_OBJECT_HANDLE hd = CK_INVALID_HANDLE;
         r.rv("derive", e.fl->C_DeriveKey(s, &m, hBase, dt, 6, &hd));
         if (hd == CK_INVALID_HANDLE) return;
         CK_ATTRIBUTE a = { CKA_VALUE, NULL_PTR, 0 };
         if (e.fl->C_GetAttributeValue(s, hd, &a, 1) != CKR_OK) { r.put("dkm", "UNREADABLE"); return; }
         std::vector<CK_BYTE> dkm(a.ulValueLen); a.pValue = dkm.data();
         e.fl->C_GetAttributeValue(s, hd, &a, 1);
         record_bytes(r, "dkm", dkm.data(), dkm.size(), ByteView::BYTES);
     }});

add({"create.generate_key_pair.ec_extra_bits", "create",
     "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS (FIPS 186-5 A.2.2) — P-256/384/521, same attribute encoding as plain CKM_EC_KEY_PAIR_GEN",
     {CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         struct Curve { const char* name; CK_BYTE* oid; CK_ULONG oidLen; };
         static CK_BYTE oidP384[] = {0x06,0x05,0x2b,0x81,0x04,0x00,0x22};
         static CK_BYTE oidP521[] = {0x06,0x05,0x2b,0x81,0x04,0x00,0x23};
         const Curve curves[] = {
             {"p256", kOidP256, sizeof kOidP256},
             {"p384", oidP384,  sizeof oidP384},
             {"p521", oidP521,  sizeof oidP521},
         };
         for (const Curve& c : curves) {
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,     &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,  &ktEc,     sizeof ktEc),
                 ATTR(CKA_EC_PARAMS, c.oid,     c.oidLen),
                 ATTR(CKA_TOKEN,     &bFalse,   sizeof bFalse),
                 ATTR(CKA_VERIFY,    &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,     &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,  &ktEc,      sizeof ktEc),
                 ATTR(CKA_TOKEN,     &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,      &bTrue,     sizeof bTrue),
                 ATTR(CKA_DERIVE,    &bTrue,     sizeof bTrue),
                 ATTR(CKA_SENSITIVE, &bTrue,     sizeof bTrue),
             };
             gen_pair(e, r, s, std::string("gen_") + c.name,
                      CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, pub, 5, priv, 6);
         }
     }});

// ---------------------------------------------------------------------------
// Exhaustive PQC coverage (2026-08-30): every ML-DSA/ML-KEM/SLH-DSA
// parameter set, keygen AND a real operation round trip (sign/verify or
// encapsulate/decapsulate), not just the one representative set per family
// the "create" group had before. Signature/ciphertext BYTES are never
// comparable across engines here (both use fresh random key pairs, and
// ML-DSA/SLH-DSA signing is hedged by default) — every check below is a
// VERDICT comparison (did it succeed, does the round trip agree, is a
// tampered value correctly rejected), the same convention
// create.encapsulate.ml_kem_768 already established.
// ---------------------------------------------------------------------------

add({"create.generate_key_pair.ml_dsa_all_params", "create",
     "ML-DSA keygen across all 3 FIPS 204 parameter sets (44/65/87)",
     {CKM_ML_DSA_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {{"44", 1}, {"65", 2}, {"87", 3}};
         for (const PS& p : sets) {
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &ktMlDsa,  sizeof ktMlDsa),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
                 ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &ktMlDsa,   sizeof ktMlDsa),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
                 ATTR(CKA_SENSITIVE,     &bFalse,    sizeof bFalse),
                 ATTR(CKA_EXTRACTABLE,   &bTrue,     sizeof bTrue),
             };
             gen_pair(e, r, s, std::string("gen_") + p.name, CKM_ML_DSA_KEY_PAIR_GEN, pub, 5, priv, 7);
         }
     }});

add({"create.sign_verify.ml_dsa_all_params", "create",
     "ML-DSA sign+verify round trip across all 3 parameter sets, plus tampered-signature rejection",
     {CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {{"44", 1}, {"65", 2}, {"87", 3}};
         for (const PS& p : sets) {
             std::string tag = p.name;
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &ktMlDsa,  sizeof ktMlDsa),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
                 ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &ktMlDsa,   sizeof ktMlDsa),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
             };
             CK_MECHANISM km = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
             CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
             CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
             r.rv(tag + ".keygen", rv);
             if (rv != CKR_OK) continue;

             CK_MECHANISM sm = { CKM_ML_DSA, NULL_PTR, 0 };
             r.rv(tag + ".sign_init", e.fl->C_SignInit(s, &sm, hPriv));
             CK_BYTE sig[16384]; CK_ULONG slen = sizeof sig;
             rv = e.fl->C_Sign(s, kPlain32, sizeof kPlain32, sig, &slen);
             r.rv(tag + ".sign", rv);
             if (rv != CKR_OK) continue;
             record_bytes(r, tag + ".sig", sig, slen, ByteView::LEN);

             r.rv(tag + ".verify_init", e.fl->C_VerifyInit(s, &sm, hPub));
             r.rv(tag + ".verify", e.fl->C_Verify(s, kPlain32, sizeof kPlain32, sig, slen));

             sig[0] ^= 0xff; // flip a bit — verify MUST now reject
             r.rv(tag + ".verify_init_tampered", e.fl->C_VerifyInit(s, &sm, hPub));
             CK_RV trv = e.fl->C_Verify(s, kPlain32, sizeof kPlain32, sig, slen);
             r.put(tag + ".tampered_correctly_rejected", (trv != CKR_OK) ? "yes" : "no");
         }
     }});

add({"create.generate_key_pair.ml_kem_all_params", "create",
     "ML-KEM keygen across all 3 FIPS 203 parameter sets (512/768/1024)",
     {CKM_ML_KEM_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {{"512", 1}, {"768", 2}, {"1024", 3}};
         for (const PS& p : sets) {
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &ktMlKem,  sizeof ktMlKem),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
                 ATTR(CKA_ENCAPSULATE,   &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &ktMlKem,   sizeof ktMlKem),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_DECAPSULATE,   &bTrue,     sizeof bTrue),
                 ATTR(CKA_SENSITIVE,     &bFalse,    sizeof bFalse),
                 ATTR(CKA_EXTRACTABLE,   &bTrue,     sizeof bTrue),
             };
             gen_pair(e, r, s, std::string("gen_") + p.name, CKM_ML_KEM_KEY_PAIR_GEN, pub, 5, priv, 7);
         }
     }});

add({"create.encapsulate.ml_kem_all_params", "create",
     "C_EncapsulateKey / C_DecapsulateKey across all 3 ML-KEM parameter sets — same convention as create.encapsulate.ml_kem_768",
     {CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         if (!e.Encapsulate || !e.Decapsulate) { r.put("fn", "ABSENT"); return; }
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {{"512", 1}, {"1024", 3}}; // 768 already covered by create.encapsulate.ml_kem_768
         for (const PS& p : sets) {
             std::string tag = p.name;
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic,  sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &ktMlKem,   sizeof ktMlKem),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_ENCAPSULATE,   &bTrue,     sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &ktMlKem,   sizeof ktMlKem),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_DECAPSULATE,   &bTrue,     sizeof bTrue),
             };
             CK_MECHANISM km = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
             CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
             CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
             r.rv(tag + ".keygen", rv);
             if (rv != CKR_OK) continue;
             CK_ATTRIBUTE st[] = {
                 ATTR(CKA_CLASS,       &clSecret,  sizeof clSecret),
                 ATTR(CKA_KEY_TYPE,    &ktGeneric, sizeof ktGeneric),
                 ATTR(CKA_VALUE_LEN,   &len32,     sizeof len32),
                 ATTR(CKA_TOKEN,       &bFalse,    sizeof bFalse),
                 ATTR(CKA_EXTRACTABLE, &bTrue,     sizeof bTrue),
                 ATTR(CKA_SENSITIVE,   &bFalse,    sizeof bFalse),
             };
             CK_MECHANISM em = { CKM_ML_KEM, NULL_PTR, 0 };
             CK_BYTE ct[4096]; CK_ULONG ctLen = sizeof ct;
             CK_OBJECT_HANDLE hEnc = CK_INVALID_HANDLE, hDec = CK_INVALID_HANDLE;
             rv = e.Encapsulate(s, &em, hPub, st, 6, ct, &ctLen, &hEnc);
             r.rv(tag + ".encapsulate", rv);
             if (rv == CKR_OK) record_bytes(r, tag + ".ciphertext", ct, ctLen, ByteView::LEN);
             if (rv != CKR_OK) continue;
             rv = e.Decapsulate(s, &em, hPriv, st, 6, ct, ctLen, &hDec);
             r.rv(tag + ".decapsulate", rv);
             auto val = [&](CK_OBJECT_HANDLE h, std::vector<CK_BYTE>& out) {
                 CK_ATTRIBUTE a = { CKA_VALUE, NULL_PTR, 0 };
                 if (e.fl->C_GetAttributeValue(s, h, &a, 1) != CKR_OK || a.ulValueLen == (CK_ULONG)-1) return false;
                 out.resize(a.ulValueLen); a.pValue = out.data();
                 return e.fl->C_GetAttributeValue(s, h, &a, 1) == CKR_OK;
             };
             std::vector<CK_BYTE> v1, v2;
             bool ok = val(hEnc, v1) && val(hDec, v2) && !v1.empty() && v1 == v2;
             r.put(tag + ".shared_secret_agrees", ok ? "yes" : "no");
         }
     }});

add({"create.generate_key_pair.slh_dsa_all_params", "create",
     "SLH-DSA keygen across all 12 FIPS 205 parameter sets (SHA2/SHAKE x 128/192/256 x s/f)",
     {CKM_SLH_DSA_KEY_PAIR_GEN}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x0000004bUL; // CKK_SLH_DSA
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {
             {"sha2_128s", 1}, {"shake_128s", 2}, {"sha2_128f", 3}, {"shake_128f", 4},
             {"sha2_192s", 5}, {"shake_192s", 6}, {"sha2_192f", 7}, {"shake_192f", 8},
             {"sha2_256s", 9}, {"shake_256s", 10}, {"sha2_256f", 11}, {"shake_256f", 12},
         };
         for (const PS& p : sets) {
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &kt,       sizeof kt),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
                 ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &kt,        sizeof kt),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
             };
             gen_pair(e, r, s, std::string("gen_") + p.name, CKM_SLH_DSA_KEY_PAIR_GEN, pub, 5, priv, 5);
         }
     }});

add({"create.sign_verify.slh_dsa_all_params", "create",
     "SLH-DSA sign+verify round trip across all 12 parameter sets, plus tampered-signature rejection",
     {CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA}, true, true,
     [](Engine& e, Recorder& r, CK_SESSION_HANDLE s) {
         CK_KEY_TYPE kt = 0x0000004bUL; // CKK_SLH_DSA
         struct PS { const char* name; CK_ULONG ps; };
         const PS sets[] = {
             {"sha2_128s", 1}, {"shake_128s", 2}, {"sha2_128f", 3}, {"shake_128f", 4},
             {"sha2_192s", 5}, {"shake_192s", 6}, {"sha2_192f", 7}, {"shake_192f", 8},
             {"sha2_256s", 9}, {"shake_256s", 10}, {"sha2_256f", 11}, {"shake_256f", 12},
         };
         for (const PS& p : sets) {
             std::string tag = p.name;
             // SLH-DSA sign/verify is the slow long-pole of this whole
             // suite (hash-tree computation, worst on the "s"/small-
             // signature sets) — this scenario is ONE unit of work to the
             // sharder/outer progress line, so without a print per
             // parameter set here a slow run looks indistinguishable from
             // a hung one. cpp_or_rust label added since this runs against
             // BOTH engines per iteration and either can be the slow one.
             printf("      -> %s (%s) ...", tag.c_str(), e.name.c_str());
             fflush(stdout);
             CK_ATTRIBUTE pub[] = {
                 ATTR(CKA_CLASS,         &clPublic, sizeof clPublic),
                 ATTR(CKA_KEY_TYPE,      &kt,       sizeof kt),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,   sizeof bFalse),
                 ATTR(CKA_VERIFY,        &bTrue,    sizeof bTrue),
             };
             CK_ATTRIBUTE priv[] = {
                 ATTR(CKA_CLASS,         &clPrivate, sizeof clPrivate),
                 ATTR(CKA_KEY_TYPE,      &kt,        sizeof kt),
                 ATTR(CKA_PARAMETER_SET, (CK_VOID_PTR)&p.ps, sizeof p.ps),
                 ATTR(CKA_TOKEN,         &bFalse,    sizeof bFalse),
                 ATTR(CKA_SIGN,          &bTrue,     sizeof bTrue),
             };
             CK_MECHANISM km = { CKM_SLH_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
             CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
             CK_RV rv = e.fl->C_GenerateKeyPair(s, &km, pub, 5, priv, 5, &hPub, &hPriv);
             r.rv(tag + ".keygen", rv);
             if (rv != CKR_OK) { printf(" keygen failed\n"); fflush(stdout); continue; }

             CK_MECHANISM sm = { CKM_SLH_DSA, NULL_PTR, 0 };
             r.rv(tag + ".sign_init", e.fl->C_SignInit(s, &sm, hPriv));
             CK_BYTE sig[64 * 1024]; CK_ULONG slen = sizeof sig;
             rv = e.fl->C_Sign(s, kPlain32, sizeof kPlain32, sig, &slen);
             r.rv(tag + ".sign", rv);
             if (rv != CKR_OK) { printf(" sign failed\n"); fflush(stdout); continue; }
             record_bytes(r, tag + ".sig", sig, slen, ByteView::LEN);

             r.rv(tag + ".verify_init", e.fl->C_VerifyInit(s, &sm, hPub));
             r.rv(tag + ".verify", e.fl->C_Verify(s, kPlain32, sizeof kPlain32, sig, slen));

             sig[0] ^= 0xff;
             r.rv(tag + ".verify_init_tampered", e.fl->C_VerifyInit(s, &sm, hPub));
             CK_RV trv = e.fl->C_Verify(s, kPlain32, sizeof kPlain32, sig, slen);
             r.put(tag + ".tampered_correctly_rejected", (trv != CKR_OK) ? "yes" : "no");
             printf(" ok\n");
             fflush(stdout);
         }
     }});

} // register_scenarios
