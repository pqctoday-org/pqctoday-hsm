// SPDX-License-Identifier: CC0
//
// P0-SEQUOIA-PQC-05 — §8 LIVE HSM ML-KEM SMOKE TEST.
//
// The companion to ../smoke-mldsa. The ML-DSA smoke proved the HSM *signing*
// dispatch path; this proves the HSM *KEM* dispatch path: that softhsmv3 accepts
// a cryptoki-0.12 `Mechanism::MlKem` `C_EncapsulateKey` / `C_DecapsulateKey`
// pair and that the shared secret recovered by decapsulation is byte-identical
// to the one produced by encapsulation.
//
// This is the live proof behind the bridge's composite ML-KEM decryptor
// (decryptor.rs `ml_kem_decapsulate`, §4) — that code does exactly the
// `C_DecapsulateKey(Mechanism::MlKem, ...)` call exercised here.
//
// Usage:
//   SOFTHSM2_CONF=.../smoke-softhsm2.conf \
//   cargo run -- <module.dylib> <token-label> <user-pin>
//
// Expected: encapsulation and decapsulation both succeed and the two 32-byte
// ML-KEM-768 shared secrets match.

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlKemParameterSetType, ObjectClass, ObjectHandle,
    ParameterSetType,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

// ML-KEM-768 (FIPS 203) shared-secret length and ciphertext length.
const ML_KEM_768_SS_LEN: usize = 32;
const ML_KEM_768_CT_LEN: usize = 1088;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let module = args
        .next()
        .ok_or_else(|| anyhow!("usage: smoke-mlkem <module> <token-label> <user-pin>"))?;
    let label = args.next().unwrap_or_else(|| "test".to_string());
    let pin = args.next().unwrap_or_else(|| "1234".to_string());

    println!("=== P0-SEQUOIA-PQC-05 §8 LIVE HSM ML-KEM SMOKE TEST ===");
    println!("module : {module}");
    println!("token  : {label}");
    println!("cryptoki: 0.12  (Mechanism::MlKem -> CKM_ML_KEM = 0x17)");

    // 1) Open + initialize the PKCS#11 context against the softhsmv3 module.
    let pkcs11 = Pkcs11::new(&module).context("Pkcs11::new (dlopen of module) failed")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("C_Initialize failed")?;

    // 2) Find the slot whose token has the requested label.
    let slot = find_slot(&pkcs11, &label)?;
    println!("[1] found slot {slot:?} with token label '{label}'");

    // 3) Open RW session, log in as user.
    let session = pkcs11.open_rw_session(slot).context("open_rw_session failed")?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin.clone().into())))
        .context("C_Login (user) failed")?;
    println!("[2] opened RW session, logged in as user");

    // 4) Generate an ML-KEM-768 keypair in the token.
    let (pub_handle, priv_handle) = gen_mlkem768(&session)
        .context("ML-KEM-768 key generation (CKM_ML_KEM_KEY_PAIR_GEN) failed")?;
    println!("[3] generated ML-KEM-768 keypair (pub {pub_handle:?}, priv {priv_handle:?})");

    // 5) Encapsulate to the public key: get (ciphertext, encap-side secret).
    //    The derived shared secret is created as an extractable GENERIC_SECRET
    //    so we can read CKA_VALUE back and compare it after decapsulation.
    let (ciphertext, encap_secret_handle) = session
        .encapsulate_key(&Mechanism::MlKem, pub_handle, &shared_secret_template())
        .context("C_EncapsulateKey(Mechanism::MlKem) failed")?;
    let encap_secret = read_secret_value(&session, encap_secret_handle)
        .context("reading CKA_VALUE of the encapsulation shared secret failed")?;
    println!(
        "[4] C_EncapsulateKey OK: ciphertext = {} bytes, shared secret = {} bytes",
        ciphertext.len(),
        encap_secret.len()
    );

    // 6) Decapsulate the ciphertext with the private key: get the decap-side
    //    secret, read its value back.
    let decap_secret_handle = session
        .decapsulate_key(
            &Mechanism::MlKem,
            priv_handle,
            &shared_secret_template(),
            &ciphertext,
        )
        .context("C_DecapsulateKey(Mechanism::MlKem) failed")?;
    let decap_secret = read_secret_value(&session, decap_secret_handle)
        .context("reading CKA_VALUE of the decapsulation shared secret failed")?;
    println!(
        "[5] C_DecapsulateKey OK: recovered shared secret = {} bytes",
        decap_secret.len()
    );

    println!("\n=== ASSERTION ===");

    if ciphertext.len() != ML_KEM_768_CT_LEN {
        println!(
            "NOTE: ciphertext is {} bytes (FIPS 203 ML-KEM-768 expects {ML_KEM_768_CT_LEN})",
            ciphertext.len()
        );
    }

    if encap_secret.len() != ML_KEM_768_SS_LEN || decap_secret.len() != ML_KEM_768_SS_LEN {
        bail!(
            "FAIL: shared secret length(s) unexpected: encap={}, decap={}, expected {ML_KEM_768_SS_LEN}",
            encap_secret.len(),
            decap_secret.len()
        );
    }

    if encap_secret == decap_secret {
        println!(
            "PASS: softhsmv3 ML-KEM-768 encap/decap round-trip recovered the same \
             {ML_KEM_768_SS_LEN}-byte shared secret."
        );
        println!("      ciphertext length = {} bytes", ciphertext.len());
        println!("      shared secret (hex) = {}", hex(&decap_secret));
        Ok(())
    } else {
        println!("      encap secret (hex) = {}", hex(&encap_secret));
        println!("      decap secret (hex) = {}", hex(&decap_secret));
        bail!("FAIL: encapsulated and decapsulated shared secrets differ");
    }
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

/// Generate an ML-KEM-768 keypair using the standard PKCS#11 v3.2 mechanism
/// `CKM_ML_KEM_KEY_PAIR_GEN` with `CKA_PARAMETER_SET = CKP_ML_KEM_768`.
fn gen_mlkem768(session: &Session) -> Result<(ObjectHandle, ObjectHandle)> {
    let param_set: ParameterSetType = MlKemParameterSetType::ML_KEM_768.into();

    let pub_template = vec![
        Attribute::Token(false),
        Attribute::Encapsulate(true),
        Attribute::KeyType(KeyType::ML_KEM),
        Attribute::ParameterSet(param_set),
        Attribute::Label(b"smoke-mlkem768-pub".to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Decapsulate(true),
        Attribute::KeyType(KeyType::ML_KEM),
        Attribute::Label(b"smoke-mlkem768-priv".to_vec()),
    ];

    session
        .generate_key_pair(&Mechanism::MlKemKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| anyhow!("generate_key_pair(MlKemKeyPairGen) failed: {e}"))
}

/// Template for the derived shared-secret object: an extractable GENERIC_SECRET
/// so the smoke test can read CKA_VALUE back to compare the two secrets. (In the
/// real bridge the derived secret feeds the KEM combiner — see decryptor.rs.)
fn shared_secret_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ]
}

/// Read the `CKA_VALUE` of an (extractable) secret-key object.
fn read_secret_value(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    for attribute in session.get_attributes(handle, &[AttributeType::Value])? {
        if let Attribute::Value(val) = attribute {
            return Ok(val);
        }
    }
    Err(anyhow!("derived secret object has no CKA_VALUE"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
