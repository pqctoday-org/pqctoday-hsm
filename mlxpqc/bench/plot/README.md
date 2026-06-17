# mlxpqc/bench/plot — benchmark charts (NVIDIA style)

`nvchart.py` — matplotlib PNG generator. Two styles:
- `grouped_bar(...)` — CPU vs GPU throughput (hash-chart style).
- `dual_axis(...)` — speedup + throughput, two y-axes (H100 ML-DSA/ML-KEM style).

Rule: **only plot MEASURED data.** Pass `measured=False` to stamp a
"PROJECTED — NOT MEASURED" watermark on estimates.

## Charts (measured)
- `gen_mldsa.py` → `mldsa_ntt_m5max.png` — ML-DSA NTT, CPU-1core / CPU-allcore /
  GPU throughput across batch sizes, Apple M5 Max (2026-06-13).

## Pending (need implementation before a real chart exists)
- ML-DSA keyGen / Sign / Verify — needs SHAKE kernel + sampling + packing + sign loop.
- ML-KEM keyGen / Encap / Decap — not started.
Do NOT relabel NVIDIA H100 numbers as ours.
