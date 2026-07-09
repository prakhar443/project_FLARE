#!/usr/bin/env python3
"""Reproduce all FLARE results: dataset, detection, forecasting, mitigation, plots.

Usage:
    python scripts/run_experiments.py [--outdir figures] [--no-show]

Outputs (written to --outdir):
    01_attack_no_defense.png   baseline LOFT attack overflowing an undefended switch
    02_detection_timeline.png  FLARE vs baseline detection + lead time
    03_forecast.png            time-to-overflow forecast vs ground truth
    04_mitigation.png          occupancy with FLARE mitigation enabled
    results_summary.csv        machine-readable metrics
    dataset.csv                the labeled per-window dataset
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flare.config import SimConfig
from flare.simulator import SDNSimulator
from flare.dataset import generate_dataset, generate_benign_only
from flare.evaluation import evaluate, compare_methods, false_positive_rate
from flare.mitigation import MitigationEngine


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def fig_attack_no_defense(df, cfg, outdir):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(df["t"], df["occupancy"], color="#c0392b", label="flow-table occupancy")
    ax.axhline(cfg.capacity, ls="--", color="black", label="table capacity")
    ax.axvspan(cfg.probe_start, cfg.probe_start + cfg.probe_duration,
               color="#f1c40f", alpha=0.25, label="probing phase")
    ax.axvspan(cfg.attack_start, cfg.duration, color="#e74c3c", alpha=0.12,
               label="attack phase")
    if df.attrs.get("overflow_t"):
        ax.axvline(df.attrs["overflow_t"], color="purple", ls=":",
                   label=f"overflow @ {df.attrs['overflow_t']:.0f}s")
    ax.set_xlabel("time (s)"); ax.set_ylabel("entries")
    ax.set_title("LOFT attack on an undefended SDN switch (baseline scenario)")
    ax.legend(loc="upper left", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(outdir, "01_attack_no_defense.png"), dpi=130)


def fig_detection_timeline(df, cfg, res, outdir):
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6.5), sharex=True,
                                   gridspec_kw={"height_ratios": [2, 1]})
    ax1.plot(df["t"], df["occupancy"], color="#2c3e50", label="occupancy")
    ax1.axhline(cfg.capacity, ls="--", color="black", label="capacity")
    if res.probe_t:
        ax1.axvline(res.probe_t, color="#f39c12", lw=2,
                    label=f"FLARE early-warning @ {res.probe_t:.0f}s")
    if res.flare_t:
        ax1.axvline(res.flare_t, color="#27ae60", lw=2,
                    label=f"FLARE core @ {res.flare_t:.0f}s")
    if res.baseline_t:
        ax1.axvline(res.baseline_t, color="#c0392b", lw=2,
                    label=f"baseline @ {res.baseline_t:.0f}s")
    if res.overflow_t:
        ax1.axvline(res.overflow_t, color="purple", ls=":",
                    label=f"overflow @ {res.overflow_t:.0f}s")
    ax1.set_ylabel("entries")
    ax1.set_title("Detection timeline: FLARE warns earlier than the baseline")
    ax1.legend(loc="upper left", fontsize=8)

    # Scores are produced only for windows after the start-up transient; align
    # them to the matching time axis.
    score_t = df.loc[df["t"] >= cfg.transient_skip, "t"].values[:len(res.scores)]
    ax2.plot(score_t, res.scores, color="#8e44ad", label="FLARE anomaly score")
    ax2.axhline(3.0, ls="--", color="gray", label="threshold")
    ax2.set_xlabel("time (s)"); ax2.set_ylabel("score")
    ax2.legend(loc="upper left", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(outdir, "02_detection_timeline.png"), dpi=130)


def fig_forecast(df, cfg, res, outdir):
    plt = _plt()
    if not res.forecast_curve:
        return
    fc = [(t, eta) for (t, eta, _slope) in res.forecast_curve if eta is not None]
    if not fc:
        return
    ts = [t for t, _ in fc]
    predicted = [t + eta for t, eta in fc]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(ts, predicted, color="#2980b9", label="predicted overflow time")
    if res.overflow_t:
        ax.axhline(res.overflow_t, ls="--", color="purple",
                   label=f"actual overflow @ {res.overflow_t:.0f}s")
    ax.plot(ts, ts, ls=":", color="gray", label="present (y=x)")
    ax.set_xlabel("time now (s)"); ax.set_ylabel("forecast overflow time (s)")
    ax.set_title("FLARE time-to-overflow forecast converges on the truth")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(outdir, "03_forecast.png"), dpi=130)


def fig_mitigation(df, cfg, res, outdir):
    plt = _plt()
    activate_t = res.flare_t or res.probe_t or cfg.attack_start
    mit = MitigationEngine(cfg).simulate_with_mitigation(activate_t)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(df["t"], df["occupancy"], color="#c0392b", label="no defense")
    ax.plot(mit["t"], mit["occupancy"], color="#27ae60",
            label="FLARE mitigation")
    ax.axhline(cfg.capacity, ls="--", color="black", label="capacity")
    ax.axvline(activate_t, color="#27ae60", ls=":",
               label=f"mitigation @ {activate_t:.0f}s")
    ax.set_xlabel("time (s)"); ax.set_ylabel("entries")
    ax.set_title("FLARE mitigation keeps the flow table from overflowing")
    ax.legend(loc="upper left", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(outdir, "04_mitigation.png"), dpi=130)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="figures")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    cfg = SimConfig(seed=args.seed)
    print(f"[FLARE] simulating scenario (capacity={cfg.capacity}, "
          f"idle_timeout={cfg.idle_timeout}s)...")
    df = SDNSimulator(cfg).run()
    print(f"[FLARE] overflow_t = {df.attrs.get('overflow_t')}")

    res = evaluate(df, cfg)
    print("[FLARE] detection summary:")
    for k, v in res.summary().items():
        print(f"    {k:32s}: {v}")

    print("[FLARE] building labeled dataset...")
    ds = generate_dataset(cfg, n_runs=5)
    ds.to_csv(os.path.join(args.outdir, "dataset.csv"), index=False)

    print("[FLARE] measuring false-positive rate on benign-only traffic...")
    benign = generate_benign_only(cfg, n_runs=3)
    fpr = false_positive_rate(benign, cfg)
    print(f"    false positive rate: {fpr}")

    table = compare_methods(df, cfg, benign_df=benign)
    print("\n[FLARE] method comparison:\n", table.to_string(index=False))

    # Persist machine-readable summary.
    summary = res.summary()
    summary.update({f"fpr_{k}": v for k, v in fpr.items()})
    pd.DataFrame([summary]).to_csv(
        os.path.join(args.outdir, "results_summary.csv"), index=False)

    print("[FLARE] rendering figures...")
    fig_attack_no_defense(df, cfg, args.outdir)
    fig_detection_timeline(df, cfg, res, args.outdir)
    fig_forecast(df, cfg, res, args.outdir)
    fig_mitigation(df, cfg, res, args.outdir)
    print(f"[FLARE] done. Artifacts in '{args.outdir}/'.")


if __name__ == "__main__":
    main()
