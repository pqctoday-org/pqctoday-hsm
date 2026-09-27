# PQC phase profiler

This internal crate provides diagnostic-only phase timing for the CACP FPGA
software baseline. It is enabled by the `softhsmrustv3/phase-profile` Cargo
feature and emits one JSONL record per completed operation when
`PQC_PHASE_PROFILE_OUTPUT` names a writable file.

The profiler records exclusive nanoseconds and call counts for hashing,
sampling, NTT, multiplication, encoding, tree work, comparison and remaining
orchestration. It never receives or records keys, messages, signatures,
ciphertexts, shared secrets, coefficients or intermediate hash state.

Production builds do not enable the feature. Compare diagnostic runs with and
without the output variable to quantify the timing-point overhead on the target
CPU before interpreting small phase differences.
