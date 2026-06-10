"""Packet-level SDN switch + traffic simulator.

The simulator produces, for every time window, a feature vector describing the
state of the switch's flow table together with ground-truth labels marking the
benign / probing / attack phases.  It is the single source of truth that every
detector in FLARE consumes.

Design
------
* Traffic is generated as a list of *flows*.  Each flow emits packets at a
  fixed rate for its lifetime.  We materialise packets lazily as (time, flow_id)
  events to keep memory bounded.
* The flow table is modelled exactly: an entry is installed on the first packet
  of a flow and refreshed on every subsequent matching packet.  It is evicted
  ``idle_timeout`` seconds after its last match.  If the table is full when a
  new flow's first packet arrives, the install fails and the packet is dropped
  (an *overflow drop*) -- this is the damage a LOFT attack inflicts on
  legitimate traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd

from .config import SimConfig, DEFAULT_CONFIG


# Flow "kind" codes carried alongside every generated flow.
KIND_BENIGN = 0
KIND_PROBE = 1
KIND_ATTACK = 2


@dataclass
class _Flow:
    start: float
    pps: float
    duration: float
    kind: int


class SDNSimulator:
    """Simulate an SDN switch under benign + LOFT-attack traffic."""

    def __init__(self, config: SimConfig | None = None):
        self.cfg = config or DEFAULT_CONFIG
        self.rng = np.random.default_rng(self.cfg.seed)

    # ------------------------------------------------------------------ #
    # Traffic generation
    # ------------------------------------------------------------------ #
    def _generate_benign_flows(self) -> List[_Flow]:
        cfg = self.cfg
        flows: List[_Flow] = []
        # Poisson arrivals over the whole simulation.
        n = self.rng.poisson(cfg.benign_flow_rate * cfg.duration)
        starts = self.rng.uniform(0.0, cfg.duration, size=n)
        durations = self.rng.exponential(cfg.benign_mean_duration, size=n)
        is_short = self.rng.random(n) < cfg.benign_short_frac
        for s, d, short in zip(starts, durations, is_short):
            if short:
                # 1-2 packet "blip" flows (DNS lookups, ACKs, scans...).
                flows.append(_Flow(start=float(s), pps=cfg.benign_pps,
                                   duration=float(self.rng.uniform(0.0, 0.5)),
                                   kind=KIND_BENIGN))
            else:
                flows.append(_Flow(start=float(s), pps=cfg.benign_pps,
                                   duration=float(d), kind=KIND_BENIGN))
        return flows

    def _generate_attack_flows(self) -> List[_Flow]:
        cfg = self.cfg
        if not cfg.attack_enabled:
            return []
        flows: List[_Flow] = []

        # --- Probing phase: low-rate, short-lived recon flows ------------
        n_probe = self.rng.poisson(cfg.probe_rate * cfg.probe_duration)
        probe_starts = self.rng.uniform(
            cfg.probe_start, cfg.probe_start + cfg.probe_duration, size=n_probe)
        for s in probe_starts:
            # Single-packet probes: the attacker is *measuring* the idle
            # timeout, not yet consuming table space for long.
            flows.append(_Flow(start=float(s), pps=cfg.benign_pps,
                               duration=0.0, kind=KIND_PROBE))

        # --- Attack phase: persistent low-rate flows that never expire ---
        attack_window = max(cfg.duration - cfg.attack_start, 0.0)
        n_attack = self.rng.poisson(cfg.attack_flow_rate * attack_window)
        attack_starts = self.rng.uniform(
            cfg.attack_start, cfg.duration, size=n_attack)
        # Refresh just before the idle timeout so each entry is "kept alive".
        refresh = cfg.idle_timeout - cfg.attack_refresh_margin
        pps = 1.0 / refresh
        for s in attack_starts:
            life = cfg.duration - float(s)
            flows.append(_Flow(start=float(s), pps=pps,
                               duration=life, kind=KIND_ATTACK))
        return flows

    def _materialise_packets(
        self, flows: List[_Flow]
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Expand flows into a time-sorted packet event stream.

        Returns (times, flow_ids, kinds) sorted by time.
        """
        times_parts, fid_parts, kind_parts = [], [], []
        for fid, fl in enumerate(flows):
            # number of packets: at least the install packet.
            n_pkts = max(1, int(np.floor(fl.duration * fl.pps)) + 1)
            if n_pkts == 1:
                t = np.array([fl.start])
            else:
                step = 1.0 / fl.pps
                t = fl.start + np.arange(n_pkts) * step
                t = t[t < self.cfg.duration]
                if t.size == 0:
                    t = np.array([fl.start])
            times_parts.append(t)
            fid_parts.append(np.full(t.size, fid))
            kind_parts.append(np.full(t.size, fl.kind))

        times = np.concatenate(times_parts)
        fids = np.concatenate(fid_parts)
        kinds = np.concatenate(kind_parts)
        order = np.argsort(times, kind="stable")
        return times[order], fids[order], kinds[order]

    # ------------------------------------------------------------------ #
    # Flow-table dynamics + windowed feature extraction
    # ------------------------------------------------------------------ #
    def run(self) -> pd.DataFrame:
        """Execute the simulation and return per-window features + labels."""
        cfg = self.cfg
        flows = self._generate_benign_flows() + self._generate_attack_flows()
        times, fids, kinds = self._materialise_packets(flows)

        capacity = cfg.capacity
        idle = cfg.idle_timeout
        win = cfg.window
        n_windows = cfg.n_windows

        # Flow table: flow_id -> expiry_time.
        table: dict[int, float] = {}
        first_seen: dict[int, float] = {}

        # Per-window accumulators.
        rec = {k: np.zeros(n_windows) for k in [
            "occupancy", "new_flows", "table_miss", "overflow_drops",
            "expired", "packets", "short_lived", "attack_new", "probe_new",
        ]}

        n_pkts = times.size
        p = 0
        for w in range(n_windows):
            w_end = (w + 1) * win
            # Purge entries that have already expired by the window start.
            w_start = w * win
            # Lazy purge happens during packet processing; do a sweep here for
            # accurate occupancy at the window boundary.
            # Process all packets that fall within this window.
            while p < n_pkts and times[p] < w_end:
                t = times[p]
                fid = int(fids[p])
                kind = int(kinds[p])
                # Lazy-expire on access keeps the table honest.
                if fid in table:
                    table[fid] = t + idle  # refresh
                else:
                    rec["table_miss"][w] += 1
                    if len(table) < capacity:
                        table[fid] = t + idle
                        first_seen[fid] = t
                        rec["new_flows"][w] += 1
                        if kind == KIND_ATTACK:
                            rec["attack_new"][w] += 1
                        elif kind == KIND_PROBE:
                            rec["probe_new"][w] += 1
                    else:
                        rec["overflow_drops"][w] += 1
                rec["packets"][w] += 1
                p += 1

            # Evict expired entries as of the window end.
            expired = [f for f, exp in table.items() if exp <= w_end]
            for f in expired:
                # A flow that lived < 2 window steps is "short lived".
                if w_end - first_seen.get(f, w_end) <= 2 * idle:
                    rec["short_lived"][w] += 1
                table.pop(f, None)
                first_seen.pop(f, None)
            rec["expired"][w] = len(expired)
            rec["occupancy"][w] = len(table)

        df = pd.DataFrame(rec)
        df.insert(0, "t", (np.arange(n_windows) + 1) * win)
        df = self._add_derived_features(df)
        df = self._add_labels(df)
        return df

    # ------------------------------------------------------------------ #
    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        cfg = self.cfg
        df["occupancy_ratio"] = df["occupancy"] / cfg.capacity
        # Growth (per-second slope) of occupancy, smoothed.
        df["occ_growth"] = df["occupancy"].diff().fillna(0.0) / cfg.window
        df["occ_growth_ewma"] = df["occ_growth"].ewm(span=8).mean()
        # Churn signatures useful for spotting the probing phase early.
        df["miss_rate"] = df["table_miss"] / cfg.window
        df["short_lived_rate"] = df["short_lived"] / cfg.window
        df["expiry_rate"] = df["expired"] / cfg.window
        df["install_rate"] = df["new_flows"] / cfg.window
        # Net accumulation = installs - expiries; positive & rising => filling.
        df["net_accumulation"] = (df["new_flows"] - df["expired"]) / cfg.window
        df["net_accumulation_ewma"] = df["net_accumulation"].ewm(span=8).mean()
        # Ratio of misses that do NOT lead to a quickly-expiring entry: long-
        # lived churn, a hallmark of the persistent attack phase.
        df["pps_per_flow"] = df["packets"] / df["occupancy"].replace(0, np.nan)
        df["pps_per_flow"] = df["pps_per_flow"].fillna(0.0)
        return df

    def _add_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        cfg = self.cfg
        phase = np.zeros(len(df), dtype=int)  # 0 benign
        if cfg.attack_enabled:
            probe_mask = (df["t"] > cfg.probe_start) & \
                         (df["t"] <= cfg.probe_start + cfg.probe_duration)
            attack_mask = df["t"] > cfg.attack_start
            phase[probe_mask.values] = KIND_PROBE
            phase[attack_mask.values] = KIND_ATTACK
        df["phase"] = phase  # 0 benign, 1 probe, 2 attack
        df["is_attack"] = (phase == KIND_ATTACK).astype(int)
        df["is_malicious"] = (phase != KIND_BENIGN).astype(int)
        # Ground-truth overflow time: first window where the table is, for all
        # practical purposes, full (>=98% of capacity) -- i.e. legitimate flows
        # can no longer be reliably installed.  (The final slot fluctuates and
        # may not literally reach capacity, so an exact-full test is misleading.)
        full = df.index[df["occupancy_ratio"] >= 0.98]
        df.attrs["overflow_t"] = float(df.loc[full[0], "t"]) if len(full) else None
        df.attrs["config"] = cfg.to_dict()
        return df


def feature_columns() -> List[str]:
    """The feature columns detectors are allowed to consume."""
    return [
        "occupancy_ratio", "occ_growth_ewma", "miss_rate", "short_lived_rate",
        "expiry_rate", "install_rate", "net_accumulation_ewma", "pps_per_flow",
    ]
