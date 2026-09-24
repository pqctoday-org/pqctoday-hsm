//! hashsig engine ABI v1: driver ↔ register simulator protocol tests.
//!
//! The cryptography here is a stand-in (the engine crate's tests plug in the
//! real fips205 / hbs-lms software); these tests pin the transport: records,
//! validation order, zeroisation, status mapping, degradation and recovery,
//! and the pool's try_lock / routing policy.

use pqc_hw::hashsig_device::abi::{
    self, Caps, Command, LmsParam, MerkleInput, Operation, SlhKeygenInput, SlhParam,
    SlhSignInput, Status, XmssParam, AP_DONE, AP_IDLE, AP_START, AUTH_LEAF_NONE, REG_AP_CTRL,
    REG_DMA_BYTES, REG_DMA_HI, REG_DMA_LO, REG_ISR, REG_RETURN,
};
use pqc_hw::hashsig_device::pool::{
    HashsigAccelerator, Lane, Opener, Reference, Routing, Target,
};
use pqc_hw::hashsig_device::sim::{
    Fault, MerkleFields, NoBackend, SimBackend, SimHandle, SlhSignFields,
};
use pqc_hw::hashsig_device::{Engine, Error, Health, OUTPUT_OFFSET, TENANT_TAG};
use pqc_hw::keccak::RegisterIo;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

const PHYS: u64 = 0x6800_0000;
const DMA: usize = 1 << 20;

/// Deterministic stand-in computations.
struct Toy;

fn fill(seed: &[u8], tag: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed[i % seed.len()] ^ (tag as u8).wrapping_add(i as u8))
        .collect()
}

impl SimBackend for Toy {
    fn slh_sign(&self, p: &SlhParam, f: &SlhSignFields) -> Result<Vec<u8>, Status> {
        if f.pk_root.iter().all(|b| *b == 0xff) {
            return Err(Status::RootMismatch);
        }
        Ok(fill(&f.sk_seed, f.idx_tree ^ u64::from(f.idx_leaf) ^ u64::from(f.md[0]), p.payload_bytes()))
    }
    fn slh_keygen(&self, p: &SlhParam, sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, Status> {
        Ok(sk.iter().zip(pk).map(|(a, b)| a ^ b).take(p.n).collect())
    }
    fn merkle_lms(&self, p: &LmsParam, f: &MerkleFields) -> Result<Vec<u8>, Status> {
        Ok(fill(&f.seed, u64::from(f.leaf_start), p.n * (f.subtree_height as usize + 1)))
    }
    fn merkle_xmss(&self, p: &XmssParam, f: &MerkleFields) -> Result<Vec<u8>, Status> {
        Ok(fill(&f.seed, f.tree_address, p.n * (f.subtree_height as usize + 1)))
    }
}

fn full_caps() -> Caps {
    Caps {
        caps_version: 1,
        lanes: 1,
        hash_cores: 0b111,
        clock_hz: 250_000_000,
        commands: (1 << 20) | (1 << 22) | (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26),
        slh_sign_sets: (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 9) | (1 << 10),
        slh_keygen_sets: (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 9) | (1 << 10),
        lms_families: 0b1111,
        lmots_w: 0b1111,
        lms_max_subtree_height: 10,
        xmss_families: 0b1_1111,
        xmss_max_subtree_height: 10,
        build_id: 0x041a_a370,
        max_batch: 16,
        sha256_cores: 2,
        sha512_cores: 1,
        keccak_rounds_per_clock: 1,
        generic_lanes: 1,
        ..Caps::default()
    }
}

fn engine(sim: &SimHandle) -> Engine<impl RegisterIo + Send, impl pqc_hw::hashsig_device::DmaRegion + Send> {
    Engine::new(sim.registers(), sim.dma()).unwrap()
}

fn toy_sim(caps: Caps) -> SimHandle {
    SimHandle::new(caps, DMA, PHYS, Box::new(Toy))
}

struct Seeds {
    sk: [u8; 16],
    pk: [u8; 16],
    root: [u8; 16],
    md: [u8; 21],
}

fn seeds() -> Seeds {
    Seeds {
        sk: [0x11; 16],
        pk: [0x22; 16],
        root: [0x33; 16],
        md: [0x44; 21],
    }
}

fn sign_op(s: &Seeds) -> Operation<'_> {
    Operation::SlhSign {
        param: 2,
        input: SlhSignInput {
            sk_seed: &s.sk,
            pk_seed: &s.pk,
            pk_root: &s.root,
            md: &s.md,
            idx_tree: 0x1234_5678,
            idx_leaf: 7,
        },
    }
}

#[test]
fn query_caps_round_trips_and_every_command_scrubs_the_buffer() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let caps = engine.query_caps().unwrap();
    assert_eq!(caps.slh_sign_sets, full_caps().slh_sign_sets);
    assert_eq!(caps.max_batch, 16);
    assert!(sim.dma_is_zero(), "driver zeroes the whole buffer after a command");

    let s = seeds();
    let out = engine.execute(&sign_op(&s), None).unwrap();
    assert_eq!(out.payload.len(), 7840);
    assert_eq!(out.payload, fill(&s.sk, 0x1234_5678 ^ 7 ^ 0x44, 7840));
    assert!(out.hash_steps > 0);
    assert!(sim.dma_is_zero());
    assert_eq!(sim.inputs_left_nonzero(), 0);

    engine.scrub().unwrap();
    // The counters a QUERY_CAPS returns cover the commands before it.
    let caps = engine.query_caps().unwrap();
    assert_eq!(caps.commands_completed, 3);
    assert_eq!(caps.zeroizations, 3);
}

#[test]
fn keygen_and_merkle_payloads_have_the_abi_sizes() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let (sk, pk) = ([7u8; 32], [9u8; 32]);
    let out = engine
        .execute(
            &Operation::SlhKeygen {
                param: 10,
                input: SlhKeygenInput { sk_seed: &sk, pk_seed: &pk },
            },
            None,
        )
        .unwrap();
    assert_eq!(out.payload, vec![7 ^ 9; 32]);

    let seed = [5u8; 24];
    let id = [6u8; 16];
    for (auth, zero_auth) in [(3, false), (AUTH_LEAF_NONE, true)] {
        let out = engine
            .execute(
                &Operation::Merkle {
                    param: abi::lms_param_set(0x15, 0x0F), // SHAKE256/192 H10 / W4
                    input: MerkleInput {
                        seed: &seed,
                        public: &id,
                        subtree_height: 4,
                        leaf_start: 0,
                        auth_leaf: auth,
                        layer: 0,
                        tree_address: 0,
                    },
                },
                None,
            )
            .unwrap();
        assert_eq!(out.payload.len(), 24 * 5);
        assert_eq!(out.payload[24..].iter().all(|b| *b == 0), zero_auth);
    }
}

#[test]
fn register_map_semantics() {
    let sim = toy_sim(full_caps());
    let mut regs = sim.registers();
    assert_eq!(regs.read32(REG_AP_CTRL) & AP_IDLE, AP_IDLE);
    // DMA_BYTES below 64: RETURN = -1 and nothing written.
    regs.write32(REG_DMA_LO, PHYS as u32);
    regs.write32(REG_DMA_HI, 0);
    regs.write32(REG_DMA_BYTES, 32);
    sim.with_memory(|m| m[0] = 0x48);
    regs.write32(REG_AP_CTRL, AP_START);
    let control = regs.read32(REG_AP_CTRL);
    assert_ne!(control & AP_DONE, 0);
    assert_eq!(regs.read32(REG_AP_CTRL) & AP_DONE, 0, "ap_done is clear-on-read");
    assert_eq!(regs.read32(REG_RETURN) as i32, -1);
    assert_eq!(sim.with_memory(|m| m[OUTPUT_OFFSET]), 0);
    // ISR is toggle-on-write.
    regs.write32(REG_ISR, 1);
    assert_eq!(regs.read32(REG_ISR), 1);
    regs.write32(REG_ISR, 1);
    assert_eq!(regs.read32(REG_ISR), 0);

    // ap_start while busy has no effect.
    sim.with_memory(|m| m.fill(0));
    sim.inject(Fault::Hang);
    regs.write32(REG_DMA_BYTES, DMA as u32);
    regs.write32(REG_AP_CTRL, AP_START);
    assert_eq!(regs.read32(REG_AP_CTRL) & AP_IDLE, 0);
    regs.write32(REG_AP_CTRL, AP_START);
    assert_eq!(sim.starts_while_busy(), 1);
    sim.finish_hung();
    assert_ne!(regs.read32(REG_AP_CTRL) & AP_IDLE, 0);
}

/// Writes a raw request (bypassing the driver's own checks) and returns
/// (RETURN, completion-if-written, input-region-after).
fn raw(sim: &SimHandle, edit: impl FnOnce(&mut abi::Request)) -> (i32, Option<abi::Completion>, Vec<u8>) {
    let mut request = abi::Request {
        magic: abi::REQUEST_MAGIC,
        abi_version: 1,
        header_bytes: 64,
        total_bytes: 64,
        command: Command::SlhKeygen as u32,
        flags: 0,
        param_set: 2,
        request_id: 1,
        input_offset: 64,
        input_length: 64,
        output_offset: 256,
        output_length: 64 + 16,
        tenant_tag: TENANT_TAG,
        reserved: [0; 3],
    };
    edit(&mut request);
    sim.with_memory(|m| {
        m.fill(0);
        request.encode(&mut m[..64]);
        m[64..64 + 16].fill(0xaa); // sk_seed
        m[96..96 + 16].fill(0xbb); // pk_seed
    });
    let mut regs = sim.registers();
    regs.write32(REG_DMA_LO, PHYS as u32);
    regs.write32(REG_DMA_HI, 0);
    regs.write32(REG_DMA_BYTES, DMA as u32);
    regs.write32(REG_AP_CTRL, AP_START);
    assert_ne!(regs.read32(REG_AP_CTRL) & AP_DONE, 0);
    let ret = regs.read32(REG_RETURN) as i32;
    sim.with_memory(|m| {
        let out = request.output_offset as usize;
        let completion = (out + 64 <= m.len())
            .then(|| abi::Completion::decode(&m[out..out + 64]))
            .filter(|c| c.magic == abi::COMPLETION_MAGIC);
        (ret, completion, m[64..128].to_vec())
    })
}

#[test]
fn validation_order_and_zeroisation_follow_section_4() {
    let caps = Caps {
        slh_keygen_sets: 1 << 2,
        ..full_caps()
    };
    let sim = toy_sim(caps);

    // Success: payload written, input region wiped.
    let (ret, completion, input) = raw(&sim, |_| {});
    assert_eq!(ret, 0);
    let completion = completion.unwrap();
    assert_eq!((completion.output_bytes, completion.tenant_tag), (16, TENANT_TAG));
    assert!(input.iter().all(|b| *b == 0));

    // Step 2: bad output region → BadDescriptor, no completion, input zeroed.
    let (ret, completion, input) = raw(&sim, |r| r.output_offset = 200);
    assert_eq!((ret, completion.is_none()), (-1, true));
    assert!(input.iter().all(|b| *b == 0));

    // Step 3 before step 4: bad flags with an unknown command → BadDescriptor.
    let (ret, completion, input) = raw(&sim, |r| {
        r.flags = 1;
        r.command = 19;
    });
    assert_eq!(ret, -1);
    assert_eq!(completion.unwrap().fallback_reason, 11);
    assert!(input.iter().all(|b| *b == 0));

    // Step 4: opcode 19 (slh_verify) is never implemented.
    let (ret, completion, _) = raw(&sim, |r| r.command = 19);
    assert_eq!((ret, completion.unwrap().fallback_reason), (-2, 9));

    // Step 5: an unclaimed set (f set, and an s set this build lacks).
    for param in [4, 6] {
        let (ret, completion, input) = raw(&sim, |r| r.param_set = param);
        assert_eq!(ret, -3);
        assert_eq!(completion.unwrap().output_bytes, 0);
        assert!(input.iter().all(|b| *b == 0));
    }

    // Step 6: wrong input length / short output.
    let (ret, _, _) = raw(&sim, |r| r.input_length = 60);
    assert_eq!(ret, -1);
    let (ret, _, _) = raw(&sim, |r| r.output_length = 64 + 15);
    assert_eq!(ret, -1);

    // Step 7: nonzero padding after n bytes of SK.seed.
    sim.with_memory(|m| m.fill(0));
    let (ret, completion, _) = {
        let request = abi::Request {
            magic: abi::REQUEST_MAGIC,
            abi_version: 1,
            header_bytes: 64,
            total_bytes: 64,
            command: Command::SlhKeygen as u32,
            flags: 0,
            param_set: 2,
            request_id: 5,
            input_offset: 64,
            input_length: 64,
            output_offset: 256,
            output_length: 80,
            tenant_tag: 3,
            reserved: [0; 3],
        };
        sim.with_memory(|m| {
            request.encode(&mut m[..64]);
            m[64..64 + 20].fill(0xaa); // 4 bytes past n = 16
        });
        let mut regs = sim.registers();
        regs.write32(REG_DMA_LO, PHYS as u32);
        regs.write32(REG_DMA_BYTES, DMA as u32);
        regs.write32(REG_AP_CTRL, AP_START);
        let ret = regs.read32(REG_RETURN) as i32;
        let (completion, input) = sim.with_memory(|m| (abi::Completion::decode(&m[256..320]), m[64..128].to_vec()));
        assert!(input.iter().all(|b| *b == 0));
        (ret, Some(completion), ())
    };
    assert_eq!(ret, -4);
    assert_eq!(completion.unwrap().output_bytes, 0);
}

#[test]
fn request_table_runs_every_record_and_returns_the_first_failure() {
    let sim = toy_sim(full_caps());
    let record = |id: u64, total: u32, input: u32, output: u32, param: u32| abi::Request {
        magic: abi::REQUEST_MAGIC,
        abi_version: 1,
        header_bytes: 64,
        total_bytes: total,
        command: Command::SlhKeygen as u32,
        flags: 0,
        param_set: param,
        request_id: id,
        input_offset: input,
        input_length: 64,
        output_offset: output,
        output_length: 80,
        tenant_tag: 1,
        reserved: [0; 3],
    };
    sim.with_memory(|m| {
        m.fill(0);
        record(1, 192, 256, 1024, 2).encode(&mut m[0..64]);
        record(2, 64, 320, 1152, 4).encode(&mut m[64..128]); // f set: refused
        record(3, 64, 384, 1280, 2).encode(&mut m[128..192]);
        m[256..272].fill(1);
        m[384..400].fill(3);
    });
    let mut regs = sim.registers();
    regs.write32(REG_DMA_LO, PHYS as u32);
    regs.write32(REG_DMA_BYTES, DMA as u32);
    regs.write32(REG_AP_CTRL, AP_START);
    assert_eq!(regs.read32(REG_RETURN) as i32, -3);
    sim.with_memory(|m| {
        let c1 = abi::Completion::decode(&m[1024..1088]);
        let c2 = abi::Completion::decode(&m[1152..1216]);
        let c3 = abi::Completion::decode(&m[1280..1344]);
        assert_eq!((c1.status, c1.request_id, c1.output_bytes), (0, 1, 16));
        assert_eq!((c2.status, c2.request_id), (-3, 2));
        assert_eq!((c3.status, c3.request_id, c3.output_bytes), (0, 3, 16));
        assert!(m[256..448].iter().all(|b| *b == 0), "every input region wiped");
    });
}

#[test]
fn driver_rejects_out_of_range_inputs_before_submission() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let s = seeds();
    let bad = Operation::SlhSign {
        param: 2,
        input: SlhSignInput {
            idx_leaf: 512,
            ..match sign_op(&s) {
                Operation::SlhSign { input, .. } => input,
                _ => unreachable!(),
            }
        },
    };
    assert!(matches!(engine.execute(&bad, None), Err(Error::Input(_))));
    assert_eq!(sim.executed(Command::SlhSign), 0);
    assert_eq!(engine.health(), Health::Ready);
}

#[test]
fn statuses_map_to_fallback_degrade_or_disable() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let s = seeds();
    let kat_sk = [1u8; 16];
    let kat_pk = [2u8; 16];
    let kat = Operation::SlhKeygen {
        param: 2,
        input: SlhKeygenInput { sk_seed: &kat_sk, pk_seed: &kat_pk },
    };
    let expected = vec![1 ^ 2; 16];

    // Engine-side refusal: ARM fallback, health unchanged.
    sim.inject(Fault::Status(Status::UnsupportedParameterSet));
    assert!(matches!(engine.execute(&sign_op(&s), None), Err(Error::Rejected(Status::UnsupportedParameterSet))));
    assert_eq!(engine.health(), Health::Ready);

    // RootMismatch (wrong key blob) degrades until RESET_CORE + KAT.
    let bad_root = Seeds { root: [0xff; 16], ..seeds() };
    assert!(matches!(engine.execute(&sign_op(&bad_root), None), Err(Error::Fault(Status::RootMismatch))));
    assert_eq!(engine.health(), Health::Degraded);
    assert!(matches!(engine.execute(&sign_op(&s), None), Err(Error::Unavailable(Health::Degraded))));
    assert_eq!(engine.recover(&kat, &[0u8; 16]), Health::Degraded, "wrong answer keeps it degraded");
    assert_eq!(engine.recover(&kat, &expected), Health::Ready);
    assert!(engine.execute(&sign_op(&s), None).is_ok());

    // InternalError also degrades.
    sim.inject(Fault::Status(Status::InternalError));
    assert!(matches!(engine.execute(&sign_op(&s), None), Err(Error::Fault(Status::InternalError))));
    assert_eq!(engine.health(), Health::Degraded);

    // A completion that does not echo the request is a hardware failure.
    assert_eq!(engine.recover(&kat, &expected), Health::Ready);
    sim.inject(Fault::StaleCompletion);
    assert!(matches!(engine.execute(&sign_op(&s), None), Err(Error::BadCompletion("request_id"))));
    assert_eq!(engine.health(), Health::Degraded);

    // ScrubFailure during RESET_CORE disables the engine for good.
    sim.inject(Fault::ScrubFailureOnReset);
    assert_eq!(engine.recover(&kat, &expected), Health::Disabled);
    assert_eq!(engine.recover(&kat, &expected), Health::Disabled);
    assert!(sim.dma_is_zero());
}

#[test]
fn timeout_degrades_and_the_buffer_waits_for_idle() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let s = seeds();
    sim.inject(Fault::Hang);
    let result = engine.execute(&sign_op(&s), Some(Duration::from_millis(20)));
    assert!(matches!(result, Err(Error::Timeout)));
    assert_eq!(engine.health(), Health::Degraded);
    assert!(sim.dma_is_zero(), "secrets are wiped even when the command is abandoned");
    let kat_sk = [1u8; 16];
    let kat_pk = [2u8; 16];
    let kat = Operation::SlhKeygen {
        param: 2,
        input: SlhKeygenInput { sk_seed: &kat_sk, pk_seed: &kat_pk },
    };
    // Still running: no recovery, nothing submitted.
    let before = sim.executed(Command::ResetCore);
    assert_eq!(engine.recover(&kat, &[3u8; 16]), Health::Degraded);
    assert_eq!(sim.executed(Command::ResetCore), before);
    sim.finish_hung();
    assert_eq!(engine.recover(&kat, &[3u8; 16]), Health::Ready);
    assert_eq!(sim.executed(Command::ResetCore), before + 1);
}

#[test]
fn learned_wall_time_sets_the_timeout() {
    let sim = toy_sim(full_caps());
    let mut engine = engine(&sim);
    let s = seeds();
    let op = sign_op(&s);
    let param = op.decoded_param().unwrap();
    let first = engine.timeout_for(&op, param.as_ref());
    assert!(first >= Duration::from_secs(1));
    engine.execute(&op, None).unwrap();
    assert!(engine.learned_time(Command::SlhSign, 2, 0).is_some());
    assert_eq!(engine.timeout_for(&op, param.as_ref()), Duration::from_secs(1));
}

// ---------------------------------------------------------------------------
// Pool: routing, claims, contention, fallback
// ---------------------------------------------------------------------------

fn reference() -> Reference {
    fn keygen(_: u32, sk: &[u8], pk: &[u8]) -> Option<Vec<u8>> {
        Some(sk.iter().zip(pk).map(|(a, b)| a ^ b).collect())
    }
    Reference {
        slh_keygen: Some(keygen),
        merkle: None,
    }
}

fn opener(sim: &SimHandle) -> Opener {
    let sim = sim.clone();
    Box::new(move |_| {
        Ok(Box::new(Engine::new(sim.registers(), sim.dma())?) as Box<dyn Lane>)
    })
}

fn pool(sim: &SimHandle, routing: Routing) -> HashsigAccelerator {
    HashsigAccelerator::probe(opener(sim), 1, routing, 4, reference(), None).unwrap()
}

#[test]
fn routing_parses_and_defaults_pin_sha2_to_the_cpu() {
    let default = Routing::default();
    assert_eq!((default.shake, default.sha2), (Target::Fpga, Target::Cpu));
    let r = Routing::parse("sha2=fpga").unwrap();
    assert_eq!((r.shake, r.sha2), (Target::Fpga, Target::Fpga));
    let r = Routing::parse("all=cpu, shake=fpga").unwrap();
    assert_eq!((r.shake, r.sha2), (Target::Fpga, Target::Cpu));
    assert!(Routing::parse("sha3=fpga").is_err());
    assert!(Routing::parse("sha2").is_err());

    let sim = toy_sim(full_caps());
    let accel = pool(&sim, Routing::default());
    assert!(accel.wants(Command::SlhSign, 2, 0), "SHAKE-128s → FPGA");
    assert!(!accel.wants(Command::SlhSign, 1, 0), "SHA2-128s → CPU by default");
    assert!(!accel.wants(Command::SlhSign, 4, 0), "unclaimed f set");
    assert!(accel.wants(Command::MerkleSubtree, abi::lms_param_set(0x0F, 0x0B), 5));
    assert!(!accel.wants(Command::MerkleSubtree, abi::lms_param_set(0x0F, 0x0B), 3), "below the minimum height");
    assert!(!accel.wants(Command::MerkleSubtree, abi::lms_param_set(0x0F, 0x0B), 11), "above the claimed maximum");
    assert!(!accel.wants(Command::MerkleSubtree, abi::lms_param_set(0x05, 0x03), 5), "LMS SHA-256 → CPU");
    let accel = pool(&sim, Routing::parse("sha2=fpga").unwrap());
    assert!(accel.wants(Command::SlhSign, 1, 0));
    accel.set_routing(Routing::parse("all=cpu").unwrap());
    assert!(!accel.wants(Command::SlhSign, 1, 0));
    assert!(!accel.wants(Command::SlhSign, 2, 0));
    assert_eq!(accel.routing(), Routing { shake: Target::Cpu, sha2: Target::Cpu });
    accel.set_routing(Routing::default());
    assert!(accel.wants(Command::SlhSign, 2, 0));
    accel.set_enabled(false);
    assert!(!accel.wants(Command::SlhSign, 2, 0));
}

#[test]
fn keygen_runs_twice_and_rejects_disagreeing_roots() {
    let sim = toy_sim(full_caps());
    let accel = pool(&sim, Routing::default());
    let (sk, pk) = ([3u8; 16], [5u8; 16]);
    let input = SlhKeygenInput { sk_seed: &sk, pk_seed: &pk };
    let keygen0 = sim.executed(Command::SlhKeygen);
    assert_eq!(accel.slh_keygen(2, input), Some(vec![3 ^ 5; 16]));
    assert_eq!(sim.executed(Command::SlhKeygen), keygen0 + 2);
    sim.inject(Fault::CorruptPayload);
    assert_eq!(accel.slh_keygen(2, input), None, "roots disagree: computed on ARM");
    assert_eq!(accel.stats().rejected_outputs.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn probe_refuses_an_engine_that_fails_its_known_answer_or_claims_nothing() {
    let sim = toy_sim(full_caps());
    fn wrong(_: u32, _: &[u8], _: &[u8]) -> Option<Vec<u8>> {
        Some(vec![0; 16])
    }
    let bad = Reference { slh_keygen: Some(wrong), merkle: None };
    let error = HashsigAccelerator::probe(opener(&sim), 1, Routing::default(), 4, bad, None)
        .err()
        .unwrap();
    assert!(error.contains("known-answer"), "{error}");

    let nothing = SimHandle::new(
        Caps { caps_version: 1, commands: 1 << 25, ..Caps::default() },
        DMA,
        PHYS,
        Box::new(NoBackend),
    );
    assert!(HashsigAccelerator::probe(opener(&nothing), 1, Routing::default(), 4, reference(), None).is_err());

    let v2 = SimHandle::new(Caps { caps_version: 2, ..full_caps() }, DMA, PHYS, Box::new(Toy));
    assert!(HashsigAccelerator::probe(opener(&v2), 1, Routing::default(), 4, reference(), None).is_err());
}

#[test]
fn contention_falls_back_without_waiting() {
    let sim = toy_sim(full_caps());
    let accel = Arc::new(pool(&sim, Routing::default()));
    // Hold the only engine with a hung command on one thread while another
    // thread asks for it: the second caller must get None immediately.
    sim.inject(Fault::Hang);
    let barrier = Arc::new(Barrier::new(2));
    let holder = {
        let (accel, barrier) = (accel.clone(), barrier.clone());
        std::thread::spawn(move || {
            let s = seeds();
            let input = match sign_op(&s) {
                Operation::SlhSign { input, .. } => input,
                _ => unreachable!(),
            };
            barrier.wait();
            accel.slh_sign(2, input)
        })
    };
    barrier.wait();
    std::thread::sleep(Duration::from_millis(50));
    let s = seeds();
    let input = match sign_op(&s) {
        Operation::SlhSign { input, .. } => input,
        _ => unreachable!(),
    };
    let started = std::time::Instant::now();
    assert!(accel.slh_sign(2, input).is_none());
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(accel.stats().contended.load(std::sync::atomic::Ordering::Relaxed), 1);
    sim.finish_hung();
    assert!(holder.join().unwrap().is_some());
}

#[test]
fn errors_fall_back_and_a_rejected_output_degrades_until_recovery() {
    let sim = toy_sim(full_caps());
    let accel = pool(&sim, Routing::default());
    let s = seeds();
    let input = match sign_op(&s) {
        Operation::SlhSign { input, .. } => input,
        _ => unreachable!(),
    };
    assert!(accel.slh_sign(2, input).is_some());

    sim.inject(Fault::Status(Status::InternalError));
    assert!(accel.slh_sign(2, input).is_none(), "fault → ARM");
    assert_eq!(accel.health(), vec![Some(Health::Degraded)]);
    // First call after the fault runs the recovery (RESET_CORE + KAT).
    assert!(accel.slh_sign(2, input).is_some());
    assert_eq!(accel.stats().recoveries.load(std::sync::atomic::Ordering::Relaxed), 1);

    accel.report_rejected_output();
    // The degradation is applied before the next use, and recovery is rate
    // limited, so this call stays on ARM.
    assert!(accel.slh_sign(2, input).is_none());
    assert_eq!(accel.health(), vec![Some(Health::Degraded)]);
    accel.reset_recovery_backoff();
    assert!(accel.slh_sign(2, input).is_some());
}

#[test]
fn many_threads_share_one_engine_without_corrupting_results() {
    let sim = toy_sim(full_caps());
    let accel = Arc::new(pool(&sim, Routing::default()));
    let results = Arc::new(Mutex::new((0usize, 0usize)));
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let (accel, results) = (accel.clone(), results.clone());
            std::thread::spawn(move || {
                for i in 0..20u32 {
                    let sk = [t as u8 + 1; 16];
                    let (pk, root, md) = ([2u8; 16], [3u8; 16], [i as u8; 21]);
                    let input = SlhSignInput {
                        sk_seed: &sk,
                        pk_seed: &pk,
                        pk_root: &root,
                        md: &md,
                        idx_tree: u64::from(i),
                        idx_leaf: i,
                    };
                    let result = accel.slh_sign(2, input);
                    let mut r = results.lock().unwrap();
                    match result {
                        Some(payload) => {
                            assert_eq!(payload, fill(&sk, u64::from(i as u8), 7840));
                            r.0 += 1;
                        }
                        None => r.1 += 1,
                    }
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let (hw, arm) = *results.lock().unwrap();
    assert_eq!(hw + arm, 160);
    assert!(hw > 0);
    assert_eq!(sim.starts_while_busy(), 0);
    assert!(sim.dma_is_zero());
}

#[test]
fn lms_node_subtree_maps_rfc8554_node_numbers() {
    use pqc_hw::hashsig_device::pool::lms_node_subtree;
    assert_eq!(lms_node_subtree(5, 1), Some((5, 0)));
    assert_eq!(lms_node_subtree(5, 2), Some((4, 0)));
    assert_eq!(lms_node_subtree(5, 3), Some((4, 16)));
    assert_eq!(lms_node_subtree(5, 32), Some((0, 0)));
    assert_eq!(lms_node_subtree(5, 63), Some((0, 31)));
    assert_eq!(lms_node_subtree(5, 64), None);
    assert_eq!(lms_node_subtree(5, 0), None);
}
