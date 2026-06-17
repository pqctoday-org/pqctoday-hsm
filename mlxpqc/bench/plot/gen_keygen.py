from nvchart import grouped_bar, GRAY_LT, GRAY, NV_GREEN
# MEASURED — Apple M5 Max, ML-DSA-65 keyGen (pk+sk bit-exact vs pq-crystals), 2026-06-13
grouped_bar(
    "mldsa65_keygen_m5max.png",
    "ML-DSA-65 keyGen — Apple M5 Max (40-core GPU)",
    ["256", "4,096", "65,536"],
    [("CPU 1-core",   [0.0142, 0.0167, 0.0166]),
     ("CPU 14-core",  [0.1523, 0.1658, 0.1842]),
     ("GPU (Metal)",  [0.082,  0.975,  1.705])],
    y_label="Throughput (Million keyGen/sec)",
    value_fmt="{:.3f}", colors=[GRAY_LT, GRAY, NV_GREEN],
)
print("wrote mldsa65_keygen_m5max.png")
