use crate::dma::Buffer;
use crate::keccak::{Engine, Job, Mode, Submission};
use crate::uio::Mapping;
use std::io;
use std::time::Duration;

pub struct Request<'a> {
    pub mode: Mode,
    pub input: &'a [u8],
    pub output_length: usize,
}

struct Layout {
    bytes: Vec<u8>,
    input_start: usize,
    input_size: usize,
    output_start: usize,
    output_size: usize,
    outputs: Vec<(usize, usize)>,
}

impl Layout {
    fn build(requests: &[Request<'_>]) -> io::Result<Self> {
        if requests.len() > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many jobs"));
        }
        let descriptors = requests
            .len()
            .checked_mul(32)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "batch overflow"))?;
        let input_start = align64(descriptors);
        let input_size = requests
            .iter()
            .try_fold(0usize, |n, r| n.checked_add(r.input.len()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "input overflow"))?;
        let output_start = align64(
            input_start
                .checked_add(input_size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "batch overflow"))?,
        );
        let output_size = requests
            .iter()
            .try_fold(0usize, |n, r| n.checked_add(r.output_length))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output overflow"))?;
        let total = output_start
            .checked_add(output_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "batch overflow"))?;
        let mut bytes = vec![0; total];
        let mut input_offset = 0usize;
        let mut output_offset = 0usize;
        let mut outputs = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let job = Job {
                input_offset: input_offset as u64,
                output_offset: output_offset as u64,
                input_length: u32::try_from(request.input.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "input too large"))?,
                output_length: u32::try_from(request.output_length)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "output too large"))?,
                mode: request.mode as u32,
                flags: 0,
            };
            encode_job(&mut bytes[index * 32..index * 32 + 32], job);
            bytes[input_start + input_offset..input_start + input_offset + request.input.len()]
                .copy_from_slice(request.input);
            outputs.push((output_start + output_offset, request.output_length));
            input_offset += request.input.len();
            output_offset += request.output_length;
        }
        Ok(Self {
            bytes,
            input_start,
            input_size,
            output_start,
            output_size,
            outputs,
        })
    }
}

pub fn execute_batch(requests: &[Request<'_>], timeout: Duration) -> io::Result<Vec<Vec<u8>>> {
    let mut layout = Layout::build(requests)?;
    let uio = Mapping::find_by_address("/sys/class/uio", 0xa000_0000)?;
    let mut dma = Buffer::open("/dev/pqc-accel-dma", "/sys/class/u-dma-buf/pqc-accel-dma")?;
    if layout.bytes.len() > dma.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "batch exceeds DMA buffer",
        ));
    }
    dma.as_mut_slice()[..layout.bytes.len()].copy_from_slice(&layout.bytes);
    dma.sync_for_device()?;
    let base = dma.phys_addr();
    Engine::new(Mapping::open(uio, 0x10000)?)
        .submit_polling(
            Submission {
                jobs_phys: base,
                count: requests.len() as u32,
                input_phys: base + layout.input_start as u64,
                input_capacity: layout.input_size as u64,
                output_phys: base + layout.output_start as u64,
                output_capacity: layout.output_size as u64,
            },
            timeout,
        )
        .map_err(io::Error::other)?;
    dma.sync_for_cpu()?;
    let layout_len = layout.bytes.len();
    layout.bytes.copy_from_slice(&dma.as_slice()[..layout_len]);
    Ok(layout
        .outputs
        .into_iter()
        .map(|(offset, len)| layout.bytes[offset..offset + len].to_vec())
        .collect())
}

fn align64(value: usize) -> usize {
    value.saturating_add(63) & !63
}
fn encode_job(out: &mut [u8], job: Job) {
    out[0..8].copy_from_slice(&job.input_offset.to_le_bytes());
    out[8..16].copy_from_slice(&job.output_offset.to_le_bytes());
    out[16..20].copy_from_slice(&job.input_length.to_le_bytes());
    out[20..24].copy_from_slice(&job.output_length.to_le_bytes());
    out[24..28].copy_from_slice(&job.mode.to_le_bytes());
    out[28..32].copy_from_slice(&job.flags.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expand_a_batch_layout_has_thirty_contiguous_jobs() {
        let rho = [0x5a; 32];
        let inputs: Vec<Vec<u8>> = (0u8..6)
            .flat_map(|r| (0u8..5).map(move |s| [rho.as_slice(), &[s, r]].concat()))
            .collect();
        let requests: Vec<_> = inputs
            .iter()
            .map(|input| Request {
                mode: Mode::Shake128,
                input,
                output_length: 840,
            })
            .collect();
        let layout = Layout::build(&requests).unwrap();
        assert_eq!(layout.input_start, 960);
        assert_eq!(
            u32::from_le_bytes(layout.bytes[16..20].try_into().unwrap()),
            34
        );
        assert_eq!(
            u32::from_le_bytes(layout.bytes[20..24].try_into().unwrap()),
            840
        );
        assert_eq!(
            u32::from_le_bytes(layout.bytes[24..28].try_into().unwrap()),
            Mode::Shake128 as u32
        );
        assert_eq!(
            &layout.bytes[layout.input_start..layout.input_start + 34],
            &inputs[0]
        );
        assert_eq!(layout.outputs.len(), 30);
    }
}
