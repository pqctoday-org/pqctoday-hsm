//! KV260 Keccak accelerator validation and comparison benchmark.
use pqc_hw::device::{Request, execute_batch};
#[cfg(feature = "diagnostic-timing")]
use pqc_hw::device::{StageTimes, execute_batch_timed};
use pqc_hw::keccak::Mode;
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
}
