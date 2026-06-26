from nvchart import grouped_bar, GRAY_LT, GRAY, NV_GREEN
# MEASURED — Apple M5 Max (40-core GPU), 2026-06-13 — ML-DSA NTT, million NTTs/sec
cats = ["256", "4,096", "65,536", "262,144"]
grouped_bar(
    "mldsa_ntt_m5max.png",
    "ML-DSA NTT — Apple M5 Max (40-core GPU)",
    cats,
    [("CPU 1-core",          [0.94, 1.07, 1.48, 1.50]),
     ("CPU all-cores (18)",  [1.17, 4.02, 8.14, 8.05]),
     ("GPU (Metal)",         [18.12, 57.39, 64.06, 232.24])],
    y_label="Throughput (Million NTTs/sec)",
    colors=[GRAY_LT, GRAY, NV_GREEN],
)
print("wrote mldsa_ntt_m5max.png")
