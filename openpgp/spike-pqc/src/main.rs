// SPDX-License-Identifier: CC0
//
// Feasibility spike for P0-SEQUOIA-PQC-05.
//
// Proves that the upstream sequoia `pqc` branch produces WIRE-CORRECT PQC
// OpenPGP: a detached signature made with a MLDSA65_Ed25519 (composite) key
// must carry public-key-algorithm == 30 (draft-ietf-openpgp-pqc v17, the
// MUST-implement composite signature scheme).
//
// HSM backing is intentionally NOT exercised here. The spike's only job is to
// confirm upstream emits algorithm ID 30 on the wire — the prerequisite for the
// whole migration plan. Key generation is in software.

use anyhow::{anyhow, Context, Result};
use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::types::PublicKeyAlgorithm;
use sequoia_openpgp::{Packet, PacketPile, Profile};
use std::io::Write;

// draft-ietf-openpgp-pqc v17 codepoint for the MUST-implement composite
// signature scheme ML-DSA-65 + Ed25519.
const EXPECTED_ALGO_ID: u8 = 30;

fn main() -> Result<()> {
    println!("=== P0-SEQUOIA-PQC-05 feasibility spike ===");
    println!("sequoia-openpgp: pqc branch @ rev pinned in Cargo.lock");

    let p = &StandardPolicy::new();

    // 1) Generate a composite MLDSA65_Ed25519 v6 cert in software.
    //    PQC cipher suites REQUIRE the RFC 9580 (v6) profile — v4 keys reject
    //    the PQC algorithms.
    println!("[1] generating MLDSA65_Ed25519 v6 cert (software)...");
    let (cert, _rev) = CertBuilder::new()
        .set_profile(Profile::RFC9580)
        .context("RFC9580 profile not supported")?
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .add_userid("spike@pqctoday.test")
        .add_signing_subkey()
        .generate()
        .context("cert generation failed")?;

    // Report the primary key's algorithm as sanity.
    println!(
        "    primary key pk_algo = {:?} (id {})",
        cert.primary_key().key().pk_algo(),
        u8::from(cert.primary_key().key().pk_algo())
    );

    // 2) Sign a message with the signing-capable key.
    println!("[2] producing a detached signature...");
    let keypair = cert
        .keys()
        .with_policy(p, None)
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .next()
        .ok_or_else(|| anyhow!("no signing-capable secret key found"))?
        .key()
        .clone()
        .into_keypair()
        .context("into_keypair failed")?;

    let signing_algo = keypair.public().pk_algo();
    println!(
        "    signing key pk_algo = {:?} (id {})",
        signing_algo,
        u8::from(signing_algo)
    );

    let mut sig_bytes = Vec::new();
    {
        let message = Message::new(&mut sig_bytes);
        let message = Armorer::new(message).build()?;
        let mut signer = Signer::new(message, keypair)
            .context("Signer::new failed")?
            .detached()
            .build()
            .context("Signer build failed")?;
        signer.write_all(b"pqctoday spike: prove wire algorithm ID 30")?;
        signer.finalize()?;
    }

    let armored = String::from_utf8_lossy(&sig_bytes);
    println!("[3] armored detached signature:\n{}", armored);

    // 3) Parse the produced signature packet and read its public-key-algorithm.
    let pile = PacketPile::from_bytes(&sig_bytes).context("re-parse failed")?;
    let mut found_algo: Option<PublicKeyAlgorithm> = None;
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            found_algo = Some(sig.pk_algo());
            println!(
                "[4] signature packet: version={}, pk_algo={:?} (id {})",
                sig.version(),
                sig.pk_algo(),
                u8::from(sig.pk_algo())
            );
        }
    }

    let algo = found_algo.ok_or_else(|| anyhow!("no Signature packet found in output"))?;
    let algo_id = u8::from(algo);

    // 4) De-armor to raw binary packets and show the wire bytes where the
    //    public-key-algorithm octet (0x1e == 30) lives. In an RFC 9580 v6
    //    signature packet the layout is:
    //      [tag/len][version=06][sig-type=00][pk-algo=1e][hash-algo ...]
    let mut der = sequoia_openpgp::armor::Reader::from_bytes(
        &sig_bytes,
        sequoia_openpgp::armor::ReaderMode::Tolerant(None),
    );
    let mut raw = Vec::new();
    std::io::copy(&mut der, &mut raw).context("de-armor failed")?;
    println!("[5] de-armored binary signature, first 16 bytes (hex):");
    let preview: Vec<String> = raw.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    println!("    {}", preview.join(" "));
    if let Some(pos) = raw.iter().position(|&b| b == EXPECTED_ALGO_ID) {
        println!(
            "    -> algorithm-ID octet 0x{:02x} ({}) present on the wire at offset {}",
            EXPECTED_ALGO_ID, EXPECTED_ALGO_ID, pos
        );
    }

    // 5) The assertion.
    println!("\n=== ASSERTION ===");
    if algo_id == EXPECTED_ALGO_ID {
        println!(
            "PASS: signature public-key-algorithm == {} (MLDSA65_Ed25519, draft-ietf-openpgp-pqc v17)",
            algo_id
        );
        Ok(())
    } else {
        Err(anyhow!(
            "FAIL: expected algorithm ID {} (MLDSA65_Ed25519), got {} ({:?})",
            EXPECTED_ALGO_ID,
            algo_id,
            algo
        ))
    }
}
