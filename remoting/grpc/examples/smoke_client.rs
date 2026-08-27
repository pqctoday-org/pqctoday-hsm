//! G5/H2 (docs/remoting-pkcs11-v32-residual-gaps-plan-2026-08-26.md) —
//! live-binary smoke client for the real `pqc-grpc-pkcs11` process.
//!
//! This is deliberately an EXAMPLE, not a `#[test]`: it is the "run the
//! app, not the test suite" check — a one-off manual verification tool a
//! human runs against an already-started, already-TLS-configured real
//! server, not something `cargo test`/the gate step ever builds or runs.
//! `spawn_grpc_v32` (remoting/acceptance/src/lib.rs) spins up the SAME
//! service code in-process over PLAINTEXT by design (its own doc comment
//! says TLS enforcement is covered separately, by exactly this tool) —
//! nothing in the automated suite ever drives a real protobuf call
//! through the real binary's real TLS listener. This does.
//!
//! Verifies real certificate verification (a pinned CA root via
//! `ClientTlsConfig::ca_certificate`), not a `danger_accept_invalid_certs`-
//! style bypass — the server's cert must actually chain to the CA this
//! client was told to trust.
//!
//! ## Usage
//!
//! ```text
//! # 1. Generate a cert (subjectAltName must include the domain passed
//! #    below; basicConstraints=CA:FALSE is REQUIRED — this same cert
//! #    is used as both the server's leaf identity and the client's
//! #    trusted root, and rustls-webpki rejects a leaf cert marked
//! #    CA:TRUE with InvalidCertificate(CaUsedAsEndEntity), which is
//! #    openssl's default for a bare `-x509` self-signed cert):
//! openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
//!   -days 1 -nodes -subj "/CN=localhost" \
//!   -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
//!   -addext "basicConstraints=critical,CA:FALSE" \
//!   -addext "keyUsage=critical,digitalSignature,keyEncipherment"
//!
//! # 2. Start the real binary with that identity:
//! cargo run -p pqc-grpc-pkcs11 -- --listen 127.0.0.1:18710 \
//!   --tls-cert cert.pem --tls-key key.pem --enable-destructive
//!
//! # 3. Run this client against it:
//! cargo run -p pqc-grpc-pkcs11 --example smoke_client -- \
//!   127.0.0.1:18710 cert.pem
//! ```
//!
//! Exits 0 with `SMOKE OK` printed after a full
//! OpenSession → GenerateKeyPair(ML-DSA-65) → SignInit/Sign →
//! VerifyInit/Verify → CloseSession sequence all returns `ck_rv == 0`
//! and the signature verifies for real. Exits nonzero (printing which
//! step failed and the `ck_rv` it got) otherwise.

use pqctoday_pkcs11_remote_proto as proto;
use proto::pkcs11_v32_client::Pkcs11V32Client;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

// PKCS#11 v3.2 constants this client needs — same values `verbs_v32`'s
// own `ck` module and the acceptance suite's test-local consts use.
const CKF_SERIAL_SESSION: u32 = 0x0000_0004;
const CKF_RW_SESSION: u32 = 0x0000_0002;
const CKM_ML_DSA_KEY_PAIR_GEN: u64 = 0x0000_001C;
const CKM_ML_DSA: u64 = 0x0000_001D;
const CKA_CLASS: u64 = 0x0000_0000;
const CKA_KEY_TYPE: u64 = 0x0000_0100;
const CKA_PARAMETER_SET: u64 = 0x0000_061d;
const CKA_TOKEN: u64 = 0x0000_0001;
const CKA_SIGN: u64 = 0x0000_0108;
const CKA_VERIFY: u64 = 0x0000_010a;
const CKK_ML_DSA: u32 = 0x0000_004a;
const CKO_PUBLIC_KEY: u32 = 0x0000_0002;
const CKO_PRIVATE_KEY: u32 = 0x0000_0003;
const CKP_ML_DSA_65: u32 = 0x2;

fn ulong_attr(attribute_type: u64, value: u32) -> proto::V32AttributeIn {
    proto::V32AttributeIn { attribute_type, value: (value as usize).to_le_bytes().to_vec() }
}
fn bool_attr(attribute_type: u64, value: bool) -> proto::V32AttributeIn {
    proto::V32AttributeIn { attribute_type, value: vec![u8::from(value)] }
}

fn fail(step: &str, ck_rv: u32) -> ! {
    eprintln!("SMOKE FAILED at {step}: ck_rv={ck_rv} (0x{ck_rv:x})");
    std::process::exit(1);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: smoke_client <host:port> <ca-cert.pem>");
        std::process::exit(2);
    }
    let addr = &args[1];
    let ca_pem = std::fs::read(&args[2])?;

    let tls = ClientTlsConfig::new().domain_name("localhost").ca_certificate(Certificate::from_pem(ca_pem));
    let channel = Channel::from_shared(format!("https://{addr}"))?.tls_config(tls)?.connect().await?;
    let mut client = Pkcs11V32Client::new(channel);
    println!("connected (real TLS, pinned CA, cert verified for real) to {addr}");

    let os = client.c_open_session(proto::V32OpenSessionRequest { slot_id: 0, flags: CKF_SERIAL_SESSION | CKF_RW_SESSION }).await?.into_inner();
    if os.ck_rv != 0 {
        fail("C_OpenSession", os.ck_rv);
    }
    let session_handle = os.session_handle;
    println!("C_OpenSession OK — session_handle={session_handle}");

    let public_template = vec![
        ulong_attr(CKA_CLASS, CKO_PUBLIC_KEY),
        ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA),
        ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_65),
        bool_attr(CKA_VERIFY, true),
        bool_attr(CKA_TOKEN, false),
    ];
    let private_template = vec![
        ulong_attr(CKA_CLASS, CKO_PRIVATE_KEY),
        ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA),
        ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_65),
        bool_attr(CKA_SIGN, true),
        bool_attr(CKA_TOKEN, false),
    ];
    let gkp = client
        .c_generate_key_pair(proto::V32GenerateKeyPairRequest {
            session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA_KEY_PAIR_GEN, parameter: vec![], structured: None }),
            public_key_template: public_template,
            private_key_template: private_template,
        })
        .await?
        .into_inner();
    if gkp.ck_rv != 0 {
        fail("C_GenerateKeyPair", gkp.ck_rv);
    }
    println!("C_GenerateKeyPair OK — public_handle={} private_handle={}", gkp.public_handle, gkp.private_handle);

    let msg = b"H2 live gRPC binary smoke test, real TLS, real cert verification".to_vec();
    let si = client
        .c_sign_init(proto::V32KeyedInitRequest {
            session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }),
            key_handle: gkp.private_handle,
        })
        .await?
        .into_inner();
    if si.ck_rv != 0 {
        fail("C_SignInit", si.ck_rv);
    }
    let sig = client.c_sign(proto::V32DataRequest { session_handle, data: msg.clone() }).await?.into_inner();
    if sig.ck_rv != 0 {
        fail("C_Sign", sig.ck_rv);
    }
    println!("C_Sign OK — {}-byte signature", sig.data.len());

    let vi = client
        .c_verify_init(proto::V32KeyedInitRequest {
            session_handle,
            mechanism: Some(proto::V32Mechanism { mechanism: CKM_ML_DSA, parameter: vec![], structured: None }),
            key_handle: gkp.public_handle,
        })
        .await?
        .into_inner();
    if vi.ck_rv != 0 {
        fail("C_VerifyInit", vi.ck_rv);
    }
    let v = client.c_verify(proto::V32VerifyRequest { session_handle, data: msg, signature: sig.data }).await?.into_inner();
    if v.ck_rv != 0 {
        fail("C_Verify", v.ck_rv);
    }
    println!("C_Verify OK — real signature verified over the real TLS connection");

    let cs = client.c_close_session(proto::V32SessionRequest { session_handle }).await?.into_inner();
    if cs.ck_rv != 0 {
        fail("C_CloseSession", cs.ck_rv);
    }
    println!("C_CloseSession OK");

    println!("SMOKE OK");
    Ok(())
}
