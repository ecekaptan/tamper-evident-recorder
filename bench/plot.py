"""Charts for the report, from results/overhead.json and results/checkpoint_sweep.json."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "results"

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
SERIES_1 = "#2a78d6"
SERIES_2 = "#eb6834"

LABELS = {
    "plain": "Plain JSONL logger",
    "hash": "+ Hash chain",
    "signed": "+ Signatures",
    "committed": "+ Content commitments",
    "witnessed": "+ Witness checkpoints",
}


def _style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=TEXT_2, length=0, labelsize=10)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def overhead_chart():
    rows = json.loads((RESULTS / "overhead.json").read_text())
    names = [LABELS[r["config"]] for r in rows][::-1]
    values = [r["us_per_span_median"] for r in rows][::-1]

    fig, ax = plt.subplots(figsize=(7, 3.2), facecolor=SURFACE)
    _style(ax)
    bars = ax.barh(names, values, height=0.55, color=SERIES_1)
    for bar, v in zip(bars, values):
        ax.text(v + 2, bar.get_y() + bar.get_height() / 2, f"{v:.0f} µs", va="center", fontsize=10, color=TEXT)
    ax.set_xlim(0, max(values) * 1.18)
    ax.set_xlabel("Median wall time per span (µs), through the OTel SDK", color=TEXT_2, fontsize=10)
    ax.set_title("Recording cost per agent span, by layer", loc="left", color=TEXT, fontsize=12, pad=12)
    ax.tick_params(axis="y", labelcolor=TEXT)
    fig.tight_layout()
    fig.savefig(RESULTS / "overhead.png", dpi=200)
    plt.close(fig)


def sweep_chart():
    rows = json.loads((RESULTS / "checkpoint_sweep.json").read_text())
    x = list(range(len(rows)))
    ticks = [f"every {r['checkpoint_every']}\n{r['witness_receipts']} receipts" for r in rows]
    trunc = [r["truncate_tail_detected"] * 100 for r in rows]
    rewrite = [r["full_rewrite_detected"] * 100 for r in rows]

    fig, ax = plt.subplots(figsize=(7, 3.4), facecolor=SURFACE)
    _style(ax)
    ax.grid(axis="x", visible=False)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.plot(x, rewrite, color=SERIES_1, linewidth=2, marker="o", markersize=8,
            markeredgecolor=SURFACE, markeredgewidth=2, label="Whole-chain rewrite")
    ax.plot(x, trunc, color=SERIES_2, linewidth=2, marker="s", markersize=8,
            markeredgecolor=SURFACE, markeredgewidth=2, label="Tail truncation")
    overlap = [i for i in x if trunc[i] == rewrite[i]]
    if overlap:
        ax.text((overlap[0] + overlap[-1]) / 2, 101.2, "both 100%", color=TEXT_2, fontsize=9, ha="center")
    ax.text(x[-1] + 0.12, rewrite[-1], "Rewrite", color=TEXT, fontsize=10, va="center")
    ax.text(x[-1] + 0.12, trunc[-1], "Truncation", color=TEXT, fontsize=10, va="center")
    ax.set_xticks(x, ticks)
    ax.set_xlim(-0.3, len(rows) - 0.3)
    ax.set_ylim(80, 102)
    ax.set_ylabel("Detected (%)", color=TEXT_2, fontsize=10)
    ax.set_title("Witness detection vs. checkpoint interval", loc="left", color=TEXT, fontsize=12, pad=12)
    leg = ax.legend(loc="lower left", frameon=False, fontsize=10)
    for t in leg.get_texts():
        t.set_color(TEXT)
    fig.tight_layout()
    fig.savefig(RESULTS / "checkpoint_sweep.png", dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    overhead_chart()
    sweep_chart()
    print("wrote", RESULTS / "overhead.png", "and", RESULTS / "checkpoint_sweep.png")
