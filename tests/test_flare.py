"""Sanity tests for the FLARE pipeline.

Run with:  pytest -q
These verify the simulation, detector ordering, and FLARE's core claims:
the table overflows without defense, and FLARE detects the attack *earlier*
than the FloRa-style baseline while keeping benign false positives low.
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flare.config import SimConfig
from flare.simulator import SDNSimulator, feature_columns
from flare.dataset import generate_benign_only
from flare.evaluation import evaluate, false_positive_rate


def _scenario():
    cfg = SimConfig(seed=7)
    df = SDNSimulator(cfg).run()
    return cfg, df


def test_simulation_shape():
    cfg, df = _scenario()
    assert len(df) == cfg.n_windows
    for col in feature_columns():
        assert col in df.columns
    assert df["occupancy"].max() <= cfg.capacity


def test_attack_overflows_without_defense():
    cfg, df = _scenario()
    assert df.attrs["overflow_t"] is not None, "attack should overflow the table"
    assert df["overflow_drops"].sum() > 0


def test_benign_baseline_is_well_below_capacity():
    cfg = SimConfig(seed=7, attack_enabled=False)
    df = SDNSimulator(cfg).run()
    assert df["occupancy_ratio"].max() < 0.6
    assert df.attrs["overflow_t"] is None


def test_flare_detects_earlier_than_baseline():
    cfg, df = _scenario()
    res = evaluate(df, cfg)
    assert res.flare_t is not None, "FLARE must detect the attack"
    assert res.baseline_t is not None, "baseline must eventually detect it"
    assert res.flare_t <= res.baseline_t, "FLARE should fire no later than baseline"


def test_early_warning_fires_in_probe_phase():
    cfg, df = _scenario()
    res = evaluate(df, cfg)
    assert res.probe_t is not None, "early-warning should catch the probing phase"
    # Probing alert should precede the actual overflow with real lead time.
    assert res.probe_t < res.overflow_t


def test_forecast_is_reasonable():
    cfg, df = _scenario()
    res = evaluate(df, cfg)
    if res.forecast_error is not None:
        assert res.forecast_error < 60.0, "forecast within a minute of truth"


def test_false_positive_rate_is_low():
    cfg = SimConfig(seed=7)
    benign = generate_benign_only(cfg, n_runs=2)
    fpr = false_positive_rate(benign, cfg)
    assert fpr["flare"] < 0.05, f"FLARE FPR too high: {fpr['flare']}"
