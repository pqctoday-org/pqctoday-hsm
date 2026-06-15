// SPDX-License-Identifier: CC0
//
// P0-SEQUOIA-PQC-05 — composite-half PRIVATE-KEY IMPORT probe.
//
// The composite `upload_key` path (upload.rs) must store each composite key's
// TWO component private halves as two PKCS#11 objects. sequoia hands us each PQC
// half as a *seed* (ML-DSA xi = 32 B, ML-KEM d||z = 64 B — see sequoia
// crypto/mpi.rs SecretKeyMaterial::{MLDSA65_Ed25519,MLKEM768_X25519}). But
// softhsmv3 reconstructs an ML-DSA/ML-KEM private key from CKA_VALUE interpreted
// as PKCS#8 DER (OSSL{MLDSA,MLKEM}PrivateKey::createOSSLKey -> d2i_PKCS8...).
//
// So importing a composite PQC half = build the OpenSSL EVP_PKEY from the seed
// (PKey::private_key_from_seed, OpenSSL 3.5+) and DER-encode PKCS#8
// (private_key_to_pkcs8), then store as CKA_VALUE on a C_CreateObject. This
// probe proves that exact pipeline end-to-end against the live softhsmv3 module:
//
//   [A] ML-DSA-65: seed -> PKCS#8 DER -> import -> C_Sign -> assert 3309 B
//   [B] ML-KEM-768: seed -> PKCS#8 DER (priv) + raw pub -> import both ->
//                   C_EncapsulateKey(pub) -> C_DecapsulateKey(imported priv) ->
//                   assert the two shared secrets match
//
// Usage:
//   SOFTHSM2_CONF=.../smoke-softhsm2.conf \
//   cargo run -- <module.dylib> <token-label> <user-pin>

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlDsaParameterSetType, MlKemParameterSetType, ObjectClass,
    ObjectHandle, ParameterSetType,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use openssl::pkey::{KeyType as OsslKeyType, PKey};

const ML_DSA_65_SIG_LEN: usize = 3309;
const ML_DSA_65_SEED_LEN: usize = 32; // FIPS 204 xi
const ML_KEM_768_SEED_LEN: usize = 64; // FIPS 203 d || z
const ML_KEM_768_SS_LEN: usize = 32;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let module = args
        .next()
        .ok_or_else(|| anyhow!("usage: smoke-import <module> <token-label> <user-pin>"))?;
    let label = args.next().unwrap_or_else(|| "test".to_string());
    let pin = args.next().unwrap_or_else(|| "1234".to_string());

    println!("=== P0-SEQUOIA-PQC-05 composite-half PRIVATE-KEY IMPORT probe ===");
    println!("module : {module}");
    println!("token  : {label}");
    println!("openssl: {}", openssl::version::version());

    let pkcs11 = Pkcs11::new(&module).context("Pkcs11::new failed")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("C_Initialize failed")?;
    let slot = find_slot(&pkcs11, &label)?;
    let session = pkcs11.open_rw_session(slot).context("open_rw_session failed")?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin.into())))
        .context("C_Login failed")?;
    println!("[0] session up on slot {slot:?}");

    test_mldsa_import(&session)?;
    test_mlkem_import(&session)?;
    test_ed25519_import(&session)?;
    test_x25519_import(&session)?;

    println!("\n=== ASSERTION ===");
    println!(
        "PASS: all four composite component halves import and operate in softhsmv3 \
         (ML-DSA-65 C_Sign 3309 B; ML-KEM-768 decap matches encap; Ed25519 C_Sign 64 B; \
         X25519 ECDH derive 32 B)."
    );
    Ok(())
}

/// [A] ML-DSA-65: build from a 32-byte seed, PKCS#8-DER it, import as a private
/// object (CKA_VALUE=DER), and sign — expecting a 3309-byte signature.
fn test_mldsa_import(session: &Session) -> Result<()> {
    println!("\n--- [A] ML-DSA-65 import-from-seed ---");
    let seed = [0x11u8; ML_DSA_65_SEED_LEN];

    // seed -> EVP_PKEY -> PKCS#8 DER (the exact transform upload.rs will do).
    let pkey = PKey::private_key_from_seed(None, OsslKeyType::ML_DSA_65, None, &seed)
        .context("PKey::private_key_from_seed(ML_DSA_65) failed (needs OpenSSL >= 3.5)")?;
    let pkcs8_der = pkey
        .private_key_to_pkcs8()
        .context("private_key_to_pkcs8 (ML-DSA-65) failed")?;
    println!("    seed {} B -> PKCS#8 DER {} B", seed.len(), pkcs8_der.len());

    let param_set: ParameterSetType = MlDsaParameterSetType::ML_DSA_65.into();
    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(param_set),
        Attribute::Value(pkcs8_der),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Label(b"import-mldsa65-priv".to_vec()),
    ];
    let handle = session
        .create_object(&template)
        .context("C_CreateObject(ML-DSA-65 private, CKA_VALUE=PKCS#8 DER) failed")?;
    println!("    C_CreateObject OK -> {handle:?}");

    let msg = b"pqctoday import probe: ML-DSA-65 sign on an imported-from-seed key";
    let ctx = SignAdditionalContext::new(HedgeType::Preferred, Some(&[]));
    let sig = session
        .sign(&Mechanism::MlDsa(ctx), handle, msg)
        .context("C_Sign(Mechanism::MlDsa) on imported key failed")?;
    println!("    C_Sign OK -> {} byte signature", sig.len());
    if sig.len() != ML_DSA_65_SIG_LEN {
        bail!(
            "ML-DSA-65 signature is {} bytes, expected {ML_DSA_65_SIG_LEN}",
            sig.len()
        );
    }
    println!("    [A] PASS");
    Ok(())
}

/// [B] ML-KEM-768: build from a 64-byte seed, import the private half (PKCS#8
/// DER) and the public half (raw FIPS-203 encapsulation key bytes), then
/// encapsulate to the imported pub and decapsulate with the imported priv —
/// expecting matching 32-byte shared secrets.
fn test_mlkem_import(session: &Session) -> Result<()> {
    println!("\n--- [B] ML-KEM-768 import-from-seed ---");
    let seed = [0x22u8; ML_KEM_768_SEED_LEN];

    let pkey = PKey::private_key_from_seed(None, OsslKeyType::ML_KEM_768, None, &seed)
        .context("PKey::private_key_from_seed(ML_KEM_768) failed (needs OpenSSL >= 3.5)")?;
    let pkcs8_der = pkey
        .private_key_to_pkcs8()
        .context("private_key_to_pkcs8 (ML-KEM-768) failed")?;
    let raw_pub = pkey
        .raw_public_key()
        .context("raw_public_key (ML-KEM-768 encapsulation key) failed")?;
    println!(
        "    seed {} B -> PKCS#8 DER (priv) {} B; raw pub {} B",
        seed.len(),
        pkcs8_der.len(),
        raw_pub.len()
    );

    let priv_ps: ParameterSetType = MlKemParameterSetType::ML_KEM_768.into();
    let priv_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::ML_KEM),
        Attribute::ParameterSet(priv_ps),
        Attribute::Value(pkcs8_der),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Decapsulate(true),
        Attribute::Label(b"import-mlkem768-priv".to_vec()),
    ];
    let priv_handle = session
        .create_object(&priv_template)
        .context("C_CreateObject(ML-KEM-768 private, CKA_VALUE=PKCS#8 DER) failed")?;
    println!("    C_CreateObject(priv) OK -> {priv_handle:?}");

    let pub_ps: ParameterSetType = MlKemParameterSetType::ML_KEM_768.into();
    let pub_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::ML_KEM),
        Attribute::ParameterSet(pub_ps),
        Attribute::Value(raw_pub), // raw FIPS-203 encapsulation key bytes
        Attribute::Token(false),
        Attribute::Encapsulate(true),
        Attribute::Label(b"import-mlkem768-pub".to_vec()),
    ];
    let pub_handle = session
        .create_object(&pub_template)
        .context("C_CreateObject(ML-KEM-768 public, CKA_VALUE=raw pub) failed")?;
    println!("    C_CreateObject(pub) OK -> {pub_handle:?}");

    let (ciphertext, encap_handle) = session
        .encapsulate_key(&Mechanism::MlKem, pub_handle, &secret_template())
        .context("C_EncapsulateKey(imported pub) failed")?;
    let encap_secret = read_value(session, encap_handle)?;
    println!(
        "    C_EncapsulateKey OK -> ct {} B, secret {} B",
        ciphertext.len(),
        encap_secret.len()
    );

    let decap_handle = session
        .decapsulate_key(&Mechanism::MlKem, priv_handle, &secret_template(), &ciphertext)
        .context("C_DecapsulateKey(imported priv) failed")?;
    let decap_secret = read_value(session, decap_handle)?;
    println!("    C_DecapsulateKey OK -> secret {} B", decap_secret.len());

    if encap_secret.len() != ML_KEM_768_SS_LEN || encap_secret != decap_secret {
        bail!(
            "ML-KEM-768 import: secrets differ or wrong length (encap {} B, decap {} B)",
            encap_secret.len(),
            decap_secret.len()
        );
    }
    println!("    [B] PASS (shared secret = {})", hex(&decap_secret));
    Ok(())
}

// DER encoding of the curve OID stored as CKA_EC_PARAMS in softhsmv3
// (OSSL{ED}PrivateKey::setEC -> byteString2oid).
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70]; // 1.3.101.112
const X25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110

/// [C] Ed25519 (the MLDSA65_Ed25519 traditional half): import the raw 32-byte
/// scalar as a CKK_EC_EDWARDS private object and sign — expecting 64 bytes.
fn test_ed25519_import(session: &Session) -> Result<()> {
    println!("\n--- [C] Ed25519 import (traditional half of MLDSA65_Ed25519) ---");
    // Get a real Ed25519 scalar from OpenSSL so the key is valid.
    let pkey = PKey::generate_ed25519().context("generate Ed25519 failed")?;
    let raw = pkey.raw_private_key().context("raw_private_key (Ed25519) failed")?;
    println!("    raw scalar {} B", raw.len());

    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
        Attribute::Value(raw),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Label(b"import-ed25519-priv".to_vec()),
    ];
    let handle = session
        .create_object(&template)
        .context("C_CreateObject(Ed25519 private) failed")?;
    println!("    C_CreateObject OK -> {handle:?}");

    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
    let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
    let sig = session
        .sign(&Mechanism::Eddsa(params), handle, b"pqctoday import probe: ed25519")
        .context("C_Sign(Mechanism::Eddsa) on imported key failed")?;
    println!("    C_Sign OK -> {} byte signature", sig.len());
    if sig.len() != 64 {
        bail!("Ed25519 signature is {} bytes, expected 64", sig.len());
    }
    println!("    [C] PASS");
    Ok(())
}

/// [D] X25519 (the MLKEM768_X25519 traditional half): import the raw 32-byte
/// scalar as a CKK_EC_MONTGOMERY private object and ECDH-derive against a peer
/// public — expecting a 32-byte shared secret.
fn test_x25519_import(session: &Session) -> Result<()> {
    println!("\n--- [D] X25519 import (traditional half of MLKEM768_X25519) ---");
    let pkey = PKey::generate_x25519().context("generate X25519 failed")?;
    let raw = pkey.raw_private_key().context("raw_private_key (X25519) failed")?;
    let peer = PKey::generate_x25519().context("generate X25519 peer failed")?;
    let peer_pub = peer.raw_public_key().context("raw_public_key (X25519 peer) failed")?;
    println!("    raw scalar {} B, peer pub {} B", raw.len(), peer_pub.len());

    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_MONTGOMERY),
        Attribute::EcParams(X25519_OID_DER.to_vec()),
        Attribute::Value(raw),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Derive(true),
        Attribute::Label(b"import-x25519-priv".to_vec()),
    ];
    let handle = session
        .create_object(&template)
        .context("C_CreateObject(X25519 private) failed")?;
    println!("    C_CreateObject OK -> {handle:?}");

    use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
    let params = Ecdh1DeriveParams::new(EcKdf::null(), &peer_pub);
    let derived = session
        .derive_key(
            &Mechanism::Ecdh1Derive(params),
            handle,
            &[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::ValueLen(32u64.into()),
            ],
        )
        .context("C_DeriveKey(Mechanism::Ecdh1Derive) on imported X25519 key failed")?;
    let shared = read_value(session, derived)?;
    println!("    C_DeriveKey OK -> {} byte shared secret", shared.len());
    if shared.len() != 32 {
        bail!("X25519 ECDH shared secret is {} bytes, expected 32", shared.len());
    }
    println!("    [D] PASS (shared = {})", hex(&shared));
    Ok(())
}

fn secret_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ]
}

fn read_value(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    for attribute in session.get_attributes(handle, &[AttributeType::Value])? {
        if let Attribute::Value(val) = attribute {
            return Ok(val);
        }
    }
    Err(anyhow!("secret object has no CKA_VALUE"))
}

fn find_slot(pkcs11: &Pkcs11, label: &str) -> Result<cryptoki::slot::Slot> {
    for slot in pkcs11.get_slots_with_token()? {
        if let Ok(ti) = pkcs11.get_token_info(slot) {
            if ti.label().trim() == label {
                return Ok(slot);
            }
        }
    }
    Err(anyhow!("no slot found with token label '{label}'"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
