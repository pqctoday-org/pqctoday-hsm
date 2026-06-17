#!/usr/bin/env python3
"""NVIDIA-style benchmark charts (matplotlib -> PNG).
grouped_bar: CPU vs GPU throughput (like the hash-function chart).
dual_axis:   speedup + throughput on two y-axes (like the H100 ML-DSA/ML-KEM charts).

Only plot MEASURED data. measured=False stamps a PROJECTED watermark.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

NV_GREEN = "#76B900"
NV_GREEN_LT = "#B5D880"
GRAY = "#9AA0A6"
GRAY_LT = "#C9CDD2"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 13})


def _watermark(ax, measured):
    if not measured:
        ax.text(0.5, 0.5, "PROJECTED — NOT MEASURED", transform=ax.transAxes,
                fontsize=34, color="red", alpha=0.18, ha="center", va="center", rotation=20, weight="bold")


def grouped_bar(path, title, categories, series, y_label="Throughput",
                unit="", value_fmt="{:.0f}", measured=True, colors=None, figsize=(12.8, 7.2)):
    colors = colors or [GRAY_LT, GRAY, NV_GREEN, NV_GREEN_LT]
    fig, ax = plt.subplots(figsize=figsize)
    n = len(series); x = np.arange(len(categories)); w = 0.8 / n
    for i, (name, vals) in enumerate(series):
        bars = ax.bar(x + (i - (n-1)/2)*w, vals, w*0.92, label=name, color=colors[i % len(colors)])
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, v, (value_fmt.format(v)+(f" {unit}" if unit else "")),
                    ha="center", va="bottom", fontsize=11)
    ax.set_title(title, fontsize=24, weight="bold", pad=26)
    ax.set_ylabel(y_label, fontsize=14, weight="bold")
    ax.set_xticks(x); ax.set_xticklabels(categories)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.06), ncol=len(series), frameon=False, fontsize=13)
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, color="#E6E6E6"); ax.set_axisbelow(True)
    ax.margins(y=0.16)
    _watermark(ax, measured)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
    return path


def dual_axis(path, title, categories, speedup, throughput,
              s_label="Speedup vs. CPU", t_label="Throughput (Million ops/sec)",
              s_fmt="{:.0f}x", t_fmt="{:.1f} M ops/s", measured=True, figsize=(12.8, 7.2)):
    fig, ax = plt.subplots(figsize=figsize)
    ax2 = ax.twinx()
    x = np.arange(len(categories)); w = 0.34
    b1 = ax.bar(x - w/2, speedup, w, color=NV_GREEN, label=s_label)
    b2 = ax2.bar(x + w/2, throughput, w, color=NV_GREEN_LT, label=t_label)
    for b, v in zip(b1, speedup): ax.text(b.get_x()+b.get_width()/2, v, s_fmt.format(v), ha="center", va="bottom", fontsize=11)
    for b, v in zip(b2, throughput): ax2.text(b.get_x()+b.get_width()/2, v, t_fmt.format(v), ha="center", va="bottom", fontsize=11)
    ax.set_title(title, fontsize=24, weight="bold", pad=26)
    ax.set_ylabel("Speedup", fontsize=14, weight="bold"); ax2.set_ylabel("Throughput", fontsize=14, weight="bold")
    ax.set_xticks(x); ax.set_xticklabels(categories)
    ax.margins(y=0.18); ax2.margins(y=0.18)
    ax.spines[["top"]].set_visible(False); ax2.spines[["top"]].set_visible(False)
    ax.yaxis.grid(True, color="#E6E6E6"); ax.set_axisbelow(True)
    h1, l1 = ax.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1+h2, l1+l2, loc="upper center", bbox_to_anchor=(0.5, 1.06), ncol=2, frameon=False, fontsize=13)
    _watermark(ax, measured)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
    return path
