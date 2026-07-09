"""Mitigation: what FLARE does once an attack is confirmed.

The strategy is *selective eviction with timeout hardening*.  Malicious LOFT
flows reveal themselves by carrying almost no traffic while occupying an entry
indefinitely (very low packets-per-flow, refreshed just before the idle
timeout).  On confirmation FLARE:

1. shortens the idle timeout for suspected low-rate flows, and
2. proactively evicts the lowest-activity entries,

freeing the table for legitimate traffic.  We model the *effect* of this policy
by re-simulating with malicious flows dropped from the activation time onward,
so the demonstration can show occupancy recovering instead of overflowing.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .config import SimConfig
from .simulator import SDNSimulator, KIND_ATTACK


class MitigationEngine:
    """Re-run the scenario with FLARE's mitigation enabled at ``activate_t``."""

    def __init__(self, config: SimConfig):
        self.cfg = config

    def simulate_with_mitigation(self, activate_t: float) -> pd.DataFrame:
        """Return the per-window timeline when mitigation kicks in at activate_t.

        Malicious flows that *start* after the activation time are denied an
        entry (the policy now refuses to host low-rate non-refreshing flows),
        and previously-installed malicious entries are aggressively timed out.
        """
        sim = _MitigatedSimulator(self.cfg, activate_t)
        return sim.run()


class _MitigatedSimulator(SDNSimulator):
    def __init__(self, config: SimConfig, activate_t: float):
        super().__init__(config)
        self.activate_t = activate_t

    def run(self) -> pd.DataFrame:  # type: ignore[override]
        cfg = self.cfg
        flows = self._generate_benign_flows() + self._generate_attack_flows()
        times, fids, kinds = self._materialise_packets(flows)

        capacity, idle, win, n_windows = (
            cfg.capacity, cfg.idle_timeout, cfg.window, cfg.n_windows)
        hardened_idle = max(idle * 0.25, 2.0)  # aggressive timeout after activation

        table: dict[int, float] = {}
        first_seen: dict[int, float] = {}
        occ = np.zeros(n_windows)
        drops = np.zeros(n_windows)

        n_pkts = times.size
        p = 0
        for w in range(n_windows):
            w_end = (w + 1) * win
            active = w_end >= self.activate_t
            while p < n_pkts and times[p] < w_end:
                t = times[p]
                fid = int(fids[p])
                kind = int(kinds[p])
                # Once mitigation is live, refuse / evict suspected attack flows.
                if active and kind == KIND_ATTACK:
                    drops[w] += 1
                    p += 1
                    continue
                eff_idle = hardened_idle if active else idle
                if fid in table:
                    table[fid] = t + eff_idle
                else:
                    if len(table) < capacity:
                        table[fid] = t + eff_idle
                        first_seen[fid] = t
                    else:
                        drops[w] += 1
                p += 1
            for f in [f for f, exp in table.items() if exp <= w_end]:
                table.pop(f, None)
                first_seen.pop(f, None)
            occ[w] = len(table)

        df = pd.DataFrame({
            "t": (np.arange(n_windows) + 1) * win,
            "occupancy": occ,
            "overflow_drops": drops,
        })
        df["occupancy_ratio"] = df["occupancy"] / capacity
        df.attrs["activate_t"] = self.activate_t
        return df
