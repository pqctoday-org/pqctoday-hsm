from nvchart import dual_axis
# MEASURED — Apple M5 Max, ML-DSA-65, batch 16384, GPU vs CPU-1core, 2026-06-13
dual_axis(
    "mldsa65_ops_m5max.png",
    "ML-DSA-65 Performance: Apple M5 Max (batch 16,384)",
    ["keyGen", "Verify"],
    [89.0, 77.0],          # speedup vs CPU 1-core
    [1.534, 1.435],        # GPU throughput M ops/sec
    s_label="Speedup vs CPU (1-core)",
    t_label="GPU Throughput (Million ops/sec)",
    s_fmt="{:.0f}x", t_fmt="{:.2f} M/s",
)
print("wrote mldsa65_ops_m5max.png")
