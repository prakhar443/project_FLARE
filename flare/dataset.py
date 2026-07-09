"""Labeled-dataset generation for FLARE.

Produces reproducible, labeled per-window datasets:

* ``generate_dataset``       - one or more attack scenarios with varied seeds /
                               attack intensities, concatenated and labeled.
* ``generate_benign_only``   - attack-free traffic, used to measure the false
                               positive rate of every detector.
"""

from __future__ import annotations

from dataclasses import replace
from typing import List, Optional

import pandas as pd

from .config import SimConfig, DEFAULT_CONFIG
from .simulator import SDNSimulator


def generate_dataset(
    config: Optional[SimConfig] = None,
    n_runs: int = 5,
    attack_rates: Optional[List[float]] = None,
) -> pd.DataFrame:
    """Generate a labeled dataset across several randomized attack runs."""
    base = config or DEFAULT_CONFIG
    # Vary the attack intensity around the configured rate (+/- ~20%) so the
    # dataset spans a range of fill speeds, independent of the table scale.
    if attack_rates is None:
        r = base.attack_flow_rate
        attack_rates = [0.8 * r, r, 1.2 * r]
    frames = []
    for i in range(n_runs):
        rate = attack_rates[i % len(attack_rates)]
        cfg = replace(base, seed=base.seed + i, attack_flow_rate=rate,
                      attack_enabled=True)
        df = SDNSimulator(cfg).run()
        df["run_id"] = i
        df["attack_rate"] = rate
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    return out


def generate_benign_only(
    config: Optional[SimConfig] = None, n_runs: int = 3
) -> pd.DataFrame:
    """Generate attack-free runs for false-positive-rate measurement."""
    base = config or DEFAULT_CONFIG
    frames = []
    for i in range(n_runs):
        cfg = replace(base, seed=base.seed + 100 + i, attack_enabled=False)
        df = SDNSimulator(cfg).run()
        df["run_id"] = i
        frames.append(df)
    return pd.concat(frames, ignore_index=True)
