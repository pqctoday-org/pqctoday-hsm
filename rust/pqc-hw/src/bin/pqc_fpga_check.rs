//! KV260 Keccak accelerator validation and comparison benchmark.
use pqc_hw::device::{Request, execute_batch};
#[cfg(feature = "diagnostic-timing")]
use pqc_hw::device::{StageTimes, execute_batch_timed};
use pqc_hw::keccak::Mode;
use pqc_hw::mldsa_device::{
    MATRIX_COEFFICIENTS, MLDSA_N, MLDSA_Q, MLDSA65_K, MLDSA65_L, Mldsa65Session,
    OUTPUT_COEFFICIENTS, VECTOR_COEFFICIENTS,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(2);
const ACVP_MAGIC: &[u8; 8] = b"PQCAVP1\n";
const DEFAULT_ACVP: &str = "/usr/share/pqc-fpga/acvp-byte-aft.bin";
const MLDSA_VECTOR_DIGEST: [u8; 32] = [
    0xc8, 0xb7, 0x48, 0xd9, 0x46, 0xea, 0x09, 0xb8, 0xf5, 0x88, 0x07, 0x15, 0x41, 0xeb, 0x2f, 0x28,
    0x68, 0x82, 0xf7, 0xc7, 0x7a, 0x58, 0x66, 0x34, 0x04, 0x26, 0xf3, 0x82, 0xb4, 0x29, 0xa2, 0xa1,
];

#[derive(Clone, Copy)]
struct Workload {
    name: &'static str,
    mode: Mode,
    input_len: usize,
    output_len: usize,
    batch: usize,
}

fn software_hash(mode: Mode, input: &[u8], output_len: usize) -> Vec<u8> {
    match mode {
        Mode::Sha3_256 => Sha3_256::digest(input).to_vec(),
        Mode::Sha3_512 => Sha3_512::digest(input).to_vec(),
        Mode::Shake128 => {
            let mut hasher = Shake128::default();
            Update::update(&mut hasher, input);
            let mut output = vec![0; output_len];
            XofReader::read(&mut hasher.finalize_xof(), &mut output);
            output
        }
        Mode::Shake256 => {
            let mut hasher = Shake256::default();
            Update::update(&mut hasher, input);
            let mut output = vec![0; output_len];
            XofReader::read(&mut hasher.finalize_xof(), &mut output);
            output
        }
    }
}

fn patterned_input(length: usize, salt: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 131 + salt * 17 + 0x5a) & 0xff) as u8)
        .collect()
}

fn bit_reverse_8(value: usize) -> usize {
    (value as u8).reverse_bits() as usize
}

fn modular_power(mut base: i64, mut exponent: usize) -> i32 {
    let modulus = i64::from(MLDSA_Q);
    let mut result = 1_i64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result as i32
}

fn mldsa_forward_ntt(poly: &[i32]) -> Vec<i32> {
    let modulus = i64::from(MLDSA_Q);
    let mut output: Vec<i64> = poly
        .iter()
        .map(|&coefficient| i64::from(coefficient).rem_euclid(modulus))
        .collect();
    let mut root_index = 0;
    for length in [128, 64, 32, 16, 8, 4, 2, 1] {
        for start in (0..MLDSA_N).step_by(2 * length) {
            root_index += 1;
            let root = i64::from(modular_power(1753, bit_reverse_8(root_index)));
            for index in start..start + length {
                let term = root * output[index + length] % modulus;
                let first = output[index];
                output[index] = (first + term) % modulus;
                output[index + length] = (first - term).rem_euclid(modulus);
            }
        }
    }
    output.into_iter().map(|value| value as i32).collect()
}

fn mldsa_inverse_ntt(poly: &[i64]) -> Vec<i32> {
    let modulus = i64::from(MLDSA_Q);
    let mut output: Vec<i64> = poly
        .iter()
        .map(|&coefficient| coefficient.rem_euclid(modulus))
        .collect();
    let mut root_index = 256;
    for length in [1, 2, 4, 8, 16, 32, 64, 128] {
        for start in (0..MLDSA_N).step_by(2 * length) {
            root_index -= 1;
            let root = -i64::from(modular_power(1753, bit_reverse_8(root_index)));
            for index in start..start + length {
                let first = output[index];
                let second = output[index + length];
                output[index] = (first + second) % modulus;
                output[index + length] = (root * (first - second)).rem_euclid(modulus);
            }
        }
    }
    output
        .into_iter()
        .map(|value| (8_347_681_i64 * value % modulus) as i32)
        .collect()
}

fn mldsa65_inputs() -> (Vec<i32>, Vec<i32>) {
    const BOUND: u32 = 1 << 17;
    let mut state = 0x4e54_5431_u32;
    let mut word = || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        state
    };
    let matrix = (0..MATRIX_COEFFICIENTS)
        .map(|_| (word() % MLDSA_Q as u32) as i32)
        .collect();
    let vector = (0..VECTOR_COEFFICIENTS)
        .map(|_| (word() % (2 * BOUND + 1)) as i32 - BOUND as i32)
        .collect();
    (matrix, vector)
}

fn software_mldsa65_matvec(matrix: &[i32], vector: &[i32]) -> Vec<i32> {
    let modulus = i64::from(MLDSA_Q);
    let transformed: Vec<_> = vector
        .chunks_exact(MLDSA_N)
        .map(mldsa_forward_ntt)
        .collect();
    let mut output = Vec::with_capacity(OUTPUT_COEFFICIENTS);
    for row in 0..MLDSA65_K {
        let mut accumulated = vec![0_i64; MLDSA_N];
        for column in 0..MLDSA65_L {
            let matrix_poly = &matrix
                [(row * MLDSA65_L + column) * MLDSA_N..(row * MLDSA65_L + column + 1) * MLDSA_N];
            for coefficient in 0..MLDSA_N {
                accumulated[coefficient] = (accumulated[coefficient]
                    + i64::from(matrix_poly[coefficient])
                        * i64::from(transformed[column][coefficient]))
                    % modulus;
            }
        }
        output.extend(mldsa_inverse_ntt(&accumulated));
    }
    output
}

fn mldsa_output_digest(output: &[i32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for coefficient in output {
        Digest::update(&mut hasher, coefficient.to_le_bytes());
    }
    hasher.finalize().into()
}

fn benchmark_mldsa65_matvec(iterations: usize) -> io::Result<()> {
    let (matrix, vector) = mldsa65_inputs();
    let expected = software_mldsa65_matvec(&matrix, &vector);
    if mldsa_output_digest(&expected) != MLDSA_VECTOR_DIGEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ML-DSA fixture digest mismatch",
        ));
    }
    let open_started = Instant::now();
    let mut session = Mldsa65Session::open()?;
    println!(
        "MLDSA_MATVEC_SESSION_OPEN\t{}",
        open_started.elapsed().as_nanos()
    );
    if session.execute(&matrix, &vector, TIMEOUT)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ML-DSA FPGA warm-up mismatch",
        ));
    }
    let mut hardware = Duration::ZERO;
    let mut software = Duration::ZERO;
    for iteration in 0..iterations {
        let started = Instant::now();
        let (actual, phases) = session.execute_profiled(&matrix, &vector, TIMEOUT)?;
        let hardware_sample = started.elapsed();
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ML-DSA FPGA differential mismatch",
            ));
        }
        let started = Instant::now();
        std::hint::black_box(software_mldsa65_matvec(
            std::hint::black_box(&matrix),
            std::hint::black_box(&vector),
        ));
        let software_sample = started.elapsed();
        hardware += hardware_sample;
        software += software_sample;
        println!(
            "MLDSA_MATVEC_SAMPLE\t{iteration}\t{}\t{}",
            hardware_sample.as_nanos(),
            software_sample.as_nanos()
        );
        println!(
            "MLDSA_MATVEC_PHASE_SAMPLE\t{iteration}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            phases.encode.as_nanos(),
            phases.sync_for_device.as_nanos(),
            phases.hardware.as_nanos(),
            phases.sync_for_cpu.as_nanos(),
            phases.decode_validate.as_nanos(),
            phases.scrub.as_nanos(),
            phases.total.as_nanos(),
        );
    }
    println!(
        "MLDSA_MATVEC_RESULT\t{iterations}\t{}\t{}\t{:.2}\t{:.2}\t{:.4}",
        hardware.as_micros(),
        software.as_micros(),
        iterations as f64 / hardware.as_secs_f64(),
        iterations as f64 / software.as_secs_f64(),
        software.as_secs_f64() / hardware.as_secs_f64()
    );
    Ok(())
}

fn benchmark_mldsa65_cached(iterations: usize) -> io::Result<()> {
    let (matrix, vector) = mldsa65_inputs();
    let expected = software_mldsa65_matvec(&matrix, &vector);
    if mldsa_output_digest(&expected) != MLDSA_VECTOR_DIGEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ML-DSA fixture digest mismatch",
        ));
    }
    let open_started = Instant::now();
    let mut session = Mldsa65Session::open()?;
    println!(
        "MLDSA_CACHED_SESSION_OPEN\t{}",
        open_started.elapsed().as_nanos()
    );
    println!(
        "MLDSA_CACHED_MATRIX_LOAD\t{}",
        session.load_matrix(&matrix)?.as_nanos()
    );
    if session.execute_cached(&vector, TIMEOUT)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ML-DSA cached FPGA warm-up mismatch",
        ));
    }
    let mut hardware = Duration::ZERO;
    let mut software = Duration::ZERO;
    for iteration in 0..iterations {
        let started = Instant::now();
        let (actual, phases) = session.execute_cached_profiled(&vector, TIMEOUT)?;
        let hardware_sample = started.elapsed();
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ML-DSA cached FPGA differential mismatch",
            ));
        }
        let started = Instant::now();
        std::hint::black_box(software_mldsa65_matvec(
            std::hint::black_box(&matrix),
            std::hint::black_box(&vector),
        ));
        let software_sample = started.elapsed();
        hardware += hardware_sample;
        software += software_sample;
        println!(
            "MLDSA_CACHED_SAMPLE\t{iteration}\t{}\t{}",
            hardware_sample.as_nanos(),
            software_sample.as_nanos()
        );
        println!(
            "MLDSA_CACHED_PHASE_SAMPLE\t{iteration}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            phases.encode.as_nanos(),
            phases.sync_for_device.as_nanos(),
            phases.hardware.as_nanos(),
            phases.sync_for_cpu.as_nanos(),
            phases.decode_validate.as_nanos(),
            phases.scrub.as_nanos(),
            phases.total.as_nanos(),
        );
    }
    println!(
        "MLDSA_CACHED_RESULT\t{iterations}\t{}\t{}\t{:.2}\t{:.2}\t{:.4}",
        hardware.as_micros(),
        software.as_micros(),
        iterations as f64 / hardware.as_secs_f64(),
        iterations as f64 / software.as_secs_f64(),
        software.as_secs_f64() / hardware.as_secs_f64()
    );
    Ok(())
}

fn requests<'a>(workload: Workload, inputs: &'a [Vec<u8>]) -> Vec<Request<'a>> {
    inputs
        .iter()
        .map(|input| Request {
            mode: workload.mode,
            input,
            output_length: workload.output_len,
        })
        .collect()
}

fn run_kats() -> io::Result<()> {
    pqc_hw::probe::sha3_256_self_test()?;
    let cases = [
        (Mode::Sha3_256, 32usize),
        (Mode::Sha3_512, 64usize),
        (Mode::Shake128, 256usize),
        (Mode::Shake256, 256usize),
    ];
    for (mode, output_len) in cases {
        let request = [Request {
            mode,
            input: b"abc",
            output_length: output_len,
        }];
        let hardware = execute_batch(&request, TIMEOUT)?;
        let expected = software_hash(mode, b"abc", output_len);
        if hardware.as_slice() != [expected] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{mode:?} known-answer mismatch"),
            ));
        }
        println!("KAT\t{mode:?}\tPASS");
    }
    Ok(())
}

fn benchmark(workload: Workload, iterations: usize) -> io::Result<()> {
    let inputs: Vec<_> = (0..workload.batch)
        .map(|salt| patterned_input(workload.input_len, salt))
        .collect();
    let batch_requests = requests(workload, &inputs);

    let hardware_warmup = execute_batch(&batch_requests, TIMEOUT)?;
    let expected: Vec<_> = inputs
        .iter()
        .map(|input| software_hash(workload.mode, input, workload.output_len))
        .collect();
    if hardware_warmup != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} warm-up differential mismatch", workload.name),
        ));
    }

    let mut hardware_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let output = execute_batch(&batch_requests, TIMEOUT)?;
        hardware_samples.push(started.elapsed());
        if output != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} hardware differential mismatch", workload.name),
            ));
        }
    }
    let hardware: Duration = hardware_samples.iter().copied().sum();

    let mut software_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        for input in &inputs {
            std::hint::black_box(software_hash(
                workload.mode,
                std::hint::black_box(input),
                workload.output_len,
            ));
        }
        software_samples.push(started.elapsed());
    }
    let software: Duration = software_samples.iter().copied().sum();
    let bytes_processed = workload.batch * (workload.input_len + workload.output_len);
    for (iteration, (hardware_sample, software_sample)) in
        hardware_samples.iter().zip(&software_samples).enumerate()
    {
        println!(
            "SAMPLE\t{}\t{}\t{}\t{}\t{}\t{}",
            workload.name,
            iteration,
            hardware_sample.as_nanos(),
            software_sample.as_nanos(),
            workload.batch,
            bytes_processed,
        );
    }
    let jobs = (iterations * workload.batch) as f64;
    let hardware_rate = jobs / hardware.as_secs_f64();
    let software_rate = jobs / software.as_secs_f64();
    println!(
        "RESULT\t{}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{:.4}",
        workload.name,
        workload.mode,
        workload.input_len,
        workload.output_len,
        workload.batch,
        hardware.as_micros(),
        software.as_micros(),
        hardware_rate,
        software_rate,
        software.as_secs_f64() / hardware.as_secs_f64(),
    );
    Ok(())
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_acvp_case(reader: &mut impl Read) -> io::Result<(Mode, u32, Vec<u8>, Vec<u8>)> {
    let mut mode_byte = [0];
    reader.read_exact(&mut mode_byte)?;
    let mode = match mode_byte[0] {
        1 => Mode::Sha3_256,
        2 => Mode::Sha3_512,
        3 => Mode::Shake128,
        4 => Mode::Shake256,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ACVP mode",
            ));
        }
    };
    let tc_id = read_u32(reader)?;
    let input_len = read_u32(reader)? as usize;
    let output_len = read_u32(reader)? as usize;
    if input_len > 8192 || output_len == 0 || output_len > 8192 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ACVP length",
        ));
    }
    let mut input = vec![0; input_len];
    let mut expected = vec![0; output_len];
    reader.read_exact(&mut input)?;
    reader.read_exact(&mut expected)?;
    Ok((mode, tc_id, input, expected))
}

fn run_acvp(path: &Path) -> io::Result<()> {
    let mut reader = File::open(path)?;
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    if &magic != ACVP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ACVP fixture",
        ));
    }
    let count = read_u32(&mut reader)?;
    if count != 547 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected ACVP case count",
        ));
    }
    let mut by_mode = [0u32; 4];
    for _ in 0..count {
        let (mode, tc_id, input, expected) = read_acvp_case(&mut reader)?;
        if software_hash(mode, &input, expected.len()) != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{mode:?} tcId={tc_id} fixture/software mismatch"),
            ));
        }
        let request = [Request {
            mode,
            input: &input,
            output_length: expected.len(),
        }];
        let output = execute_batch(&request, TIMEOUT)?;
        if output.as_slice() != [expected] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{mode:?} tcId={tc_id} FPGA output mismatch"),
            ));
        }
        by_mode[(mode as usize) - 1] += 1;
    }
    let mut trailing = [0];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing ACVP data",
        ));
    }
    if by_mode != [151, 86, 269, 41] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACVP mode counts differ",
        ));
    }
    println!("ACVP\tSHA3-256\t{}\tPASS", by_mode[0]);
    println!("ACVP\tSHA3-512\t{}\tPASS", by_mode[1]);
    println!("ACVP\tSHAKE128\t{}\tPASS", by_mode[2]);
    println!("ACVP\tSHAKE256\t{}\tPASS", by_mode[3]);
    println!("ACVP\tTOTAL\t{count}\tPASS");
    Ok(())
}

fn parse_iterations() -> Result<usize, String> {
    let value = env::args().nth(1).unwrap_or_else(|| "20".to_owned());
    let iterations = value
        .parse::<usize>()
        .map_err(|_| format!("invalid iteration count: {value}"))?;
    if iterations == 0 {
        return Err("iteration count must be greater than zero".to_owned());
    }
    Ok(iterations)
}

#[cfg(feature = "diagnostic-timing")]
fn profile(workload: Workload, iterations: usize) -> io::Result<()> {
    let inputs: Vec<_> = (0..workload.batch)
        .map(|salt| patterned_input(workload.input_len, salt))
        .collect();
    let batch_requests = requests(workload, &inputs);
    let expected: Vec<_> = inputs
        .iter()
        .map(|input| software_hash(workload.mode, input, workload.output_len))
        .collect();
    for iteration in 0..iterations {
        let mut times = StageTimes::default();
        let started = Instant::now();
        let output = execute_batch_timed(&batch_requests, TIMEOUT, &mut times)?;
        let end_to_end = started.elapsed();
        if output != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} differential mismatch", workload.name),
            ));
        }
        println!(
            "STAGE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            workload.name,
            iteration,
            workload.batch,
            workload.input_len,
            workload.output_len,
            end_to_end.as_nanos(),
            times.total().as_nanos(),
            times.layout.as_nanos(),
            times.uio_discovery.as_nanos(),
            times.dma_open_map.as_nanos(),
            times.input_copy.as_nanos(),
            times.device_sync.as_nanos(),
            times.uio_open_map.as_nanos(),
            times.registers.as_nanos(),
            times.start_to_done.as_nanos(),
            times.cpu_sync.as_nanos(),
            times.output_copy.as_nanos(),
            times.scrub_sync.as_nanos(),
            times.unmap.as_nanos(),
            end_to_end.saturating_sub(times.total()).as_nanos()
        );
    }
    Ok(())
}

#[cfg(feature = "diagnostic-timing")]
fn run_stages(iterations: usize) -> io::Result<()> {
    run_kats()?;
    println!(
        "STAGE_COLUMNS\tname\titeration\tbatch\tinput_bytes\toutput_bytes\tend_to_end_ns\tattributed_ns\tlayout_ns\tuio_discovery_ns\tdma_open_map_ns\tinput_copy_ns\tdevice_sync_ns\tuio_open_map_ns\tregisters_ns\tstart_to_done_ns\tcpu_sync_ns\toutput_copy_ns\tscrub_sync_ns\tunmap_ns\tunattributed_ns"
    );
    for (name, batch, input_len, output_len) in [
        ("shake-1", 1, 34, 840),
        ("shake-8", 8, 34, 840),
        ("shake-30", 30, 34, 840),
        ("shake-input-168", 8, 168, 840),
        ("shake-input-1024", 8, 1024, 840),
        ("shake-output-64", 8, 34, 64),
        ("shake-output-4096", 8, 34, 4096),
    ] {
        profile(
            Workload {
                name,
                mode: Mode::Shake128,
                input_len,
                output_len,
                batch,
            },
            iterations,
        )?;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut mldsa_args = env::args().skip(1);
    let mldsa_mode = mldsa_args.next();
    if matches!(
        mldsa_mode.as_deref(),
        Some("--mldsa-matvec" | "--mldsa-matvec-cached")
    ) {
        let iterations: usize = mldsa_args
            .next()
            .unwrap_or_else(|| "20".to_owned())
            .parse()?;
        if iterations == 0 || mldsa_args.next().is_some() {
            return Err("usage: pqc-fpga-check <--mldsa-matvec|--mldsa-matvec-cached> [positive-iterations]".into());
        }
        if mldsa_mode.as_deref() == Some("--mldsa-matvec-cached") {
            println!("PQC_FPGA_CHECK\tmldsa65-matvec-cached-v1");
            return Ok(benchmark_mldsa65_cached(iterations)?);
        }
        println!("PQC_FPGA_CHECK\tmldsa65-matvec-v1");
        return Ok(benchmark_mldsa65_matvec(iterations)?);
    }
    #[cfg(feature = "diagnostic-timing")]
    let mut args = env::args().skip(1);
    #[cfg(feature = "diagnostic-timing")]
    if args.next().as_deref() == Some("--stages") {
        let iterations: usize = args.next().unwrap_or_else(|| "20".to_owned()).parse()?;
        if iterations == 0 || args.next().is_some() {
            return Err("usage: pqc-fpga-check --stages [positive-iterations]".into());
        }
        println!("PQC_FPGA_CHECK\tdiagnostic-timing-v1");
        return Ok(run_stages(iterations)?);
    }
    let mut args = env::args().skip(1);
    if args.next().as_deref() == Some("--acvp") {
        let path = args.next().unwrap_or_else(|| DEFAULT_ACVP.to_owned());
        if args.next().is_some() {
            return Err("usage: pqc-fpga-check --acvp [fixture-path]".into());
        }
        println!("PQC_FPGA_CHECK\tv1");
        run_kats()?;
        return Ok(run_acvp(Path::new(&path))?);
    }
    let iterations = parse_iterations()?;
    println!("PQC_FPGA_CHECK\tv1");
    println!("ITERATIONS\t{iterations}");
    run_kats()?;
    println!(
        "COLUMNS\tname\tmode\tinput_bytes\toutput_bytes\tbatch\thardware_us\tsoftware_us\thardware_jobs_s\tsoftware_jobs_s\tspeedup"
    );
    let workloads = [
        Workload {
            name: "sha3-short",
            mode: Mode::Sha3_256,
            input_len: 3,
            output_len: 32,
            batch: 1,
        },
        Workload {
            name: "sha3-rate",
            mode: Mode::Sha3_256,
            input_len: 136,
            output_len: 32,
            batch: 1,
        },
        Workload {
            name: "shake-short",
            mode: Mode::Shake128,
            input_len: 34,
            output_len: 840,
            batch: 1,
        },
        Workload {
            name: "shake-batch-8",
            mode: Mode::Shake128,
            input_len: 34,
            output_len: 840,
            batch: 8,
        },
        Workload {
            name: "mldsa65-expand-a",
            mode: Mode::Shake128,
            input_len: 34,
            output_len: 840,
            batch: 30,
        },
        Workload {
            name: "shake256-long",
            mode: Mode::Shake256,
            input_len: 64,
            output_len: 512,
            batch: 8,
        },
    ];
    for workload in workloads {
        benchmark(workload, iterations)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL\t{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_known_answers_have_expected_prefixes() {
        assert_eq!(
            &software_hash(Mode::Sha3_256, b"abc", 32)[..4],
            &[0x3a, 0x98, 0x5d, 0xa7]
        );
        assert_eq!(
            &software_hash(Mode::Shake128, b"abc", 32)[..4],
            &[0x58, 0x81, 0x09, 0x2d]
        );
    }

    #[test]
    fn patterned_inputs_change_with_salt() {
        assert_ne!(patterned_input(34, 0), patterned_input(34, 1));
    }

    #[test]
    fn mldsa_reference_matches_committed_vector_digest() {
        let (matrix, vector) = mldsa65_inputs();
        assert_eq!(
            mldsa_output_digest(&software_mldsa65_matvec(&matrix, &vector)),
            MLDSA_VECTOR_DIGEST
        );
    }
}
