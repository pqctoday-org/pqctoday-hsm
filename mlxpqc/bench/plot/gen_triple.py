from nvchart import grouped_bar, GRAY, NV_GREEN
# MEASURED — Apple M5 Max, ML-DSA-65, batch 16384, 2026-06-13 (all bit-exact vs pq-crystals)
grouped_bar(
    "mldsa65_triple_m5max.png",
    "ML-DSA-65: GPU vs CPU (all cores) — Apple M5 Max, batch 16,384",
    ["keyGen", "Sign", "Verify"],
    [("CPU 14-core", [0.1855, 0.0461, 0.1996]),
     ("GPU (Metal)", [1.534,  0.0843, 1.435])],
    y_label="Throughput (Million ops/sec)",
    value_fmt="{:.3f}", colors=[GRAY, NV_GREEN],
)
print("wrote mldsa65_triple_m5max.png")
