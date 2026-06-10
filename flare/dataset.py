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
    attack_rates = attack_rates or [7.0, 9.0, 11.0]
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
