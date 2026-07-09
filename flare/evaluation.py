"""Evaluation: run detectors over a scenario and quantify FLARE's advantage.

The headline metrics mirror the project's claims:

* detection time          - first window each method raises an alert,
* lead time vs overflow   - how many seconds of warning before the table fills,
* lead time vs baseline   - how much earlier FLARE fires than the FloRa-style
                            baseline,
* false-positive rate     - alerts on attack-free traffic,
* forecast error          - |predicted overflow time - actual overflow time|.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from .config import SimConfig
from .detectors import (
    BaselineDetector, FlareDetector, EarlyWarningDetector, OverflowForecaster,
)
from .simulator import feature_columns


@dataclass
class RunResult:
    overflow_t: Optional[float]
    baseline_t: Optional[float]
    flare_t: Optional[float]
    probe_t: Optional[float]
    probe_start: Optional[float]
    forecast_curve: List[tuple]
    forecast_error: Optional[float]
    flare_alerts: list = field(default_factory=list)
    probe_alerts: list = field(default_factory=list)
    scores: list = field(default_factory=list)

    def lead_vs_overflow(self) -> Optional[float]:
        if self.overflow_t is None or self.flare_t is None:
            return None
        return self.overflow_t - self.flare_t

    def flare_system_t(self) -> Optional[float]:
        """FLARE's first alert from *any* component (early-warning or core)."""
        ts = [x for x in (self.probe_t, self.flare_t) if x is not None]
        return min(ts) if ts else None

    def lead_vs_baseline(self) -> Optional[float]:
        sys_t = self.flare_system_t()
        if self.baseline_t is None or sys_t is None:
            return None
        return self.baseline_t - sys_t

    def earliest_lead_vs_overflow(self) -> Optional[float]:
        """Lead using the *earliest* FLARE signal (probe or core)."""
        first = [x for x in (self.probe_t, self.flare_t) if x is not None]
        if not first or self.overflow_t is None:
            return None
        return self.overflow_t - min(first)

    def summary(self) -> Dict[str, Optional[float]]:
        return {
            "overflow_t": self.overflow_t,
            "probe_alert_t": self.probe_t,
            "flare_alert_t": self.flare_t,
            "baseline_alert_t": self.baseline_t,
            "flare_lead_vs_overflow_s": self.lead_vs_overflow(),
            "earliest_lead_vs_overflow_s": self.earliest_lead_vs_overflow(),
            "flare_lead_vs_baseline_s": self.lead_vs_baseline(),
            "forecast_error_s": self.forecast_error,
        }


def evaluate(df: pd.DataFrame, config: SimConfig) -> RunResult:
    """Stream a single scenario through every detector."""
    feats = feature_columns()
    baseline = BaselineDetector()
    flare = FlareDetector(features=feats)
    early = EarlyWarningDetector()
    forecaster = OverflowForecaster(capacity=config.capacity)

    overflow_t = df.attrs.get("overflow_t")
    forecast_error = None

    for _, r in df.iterrows():
        t = float(r["t"])
        # Skip the initial empty-table fill-up transient: detectors come online
        # only once the switch has reached steady-state benign operation.
        if t < config.transient_skip:
            continue
        row = {f: float(r[f]) for f in feats}
        baseline.update(t, row)
        flare.update(t, row)
        early.update(t, row)
        eta = forecaster.update(t, float(r["occupancy"]))
        if (eta is not None and overflow_t is not None and forecast_error is None
                and t < overflow_t and float(r["occupancy_ratio"]) >= 0.6):
            # Record accuracy of the first forecast made once a clear, sustained
            # fill is underway (occupancy >= 60%): this is the actionable ETA an
            # operator would act on, well before the table is full.
            predicted = t + eta
            forecast_error = abs(predicted - overflow_t)

    return RunResult(
        overflow_t=overflow_t,
        baseline_t=baseline.first_alert,
        flare_t=flare.first_alert,
        probe_t=early.first_alert,
        probe_start=config.probe_start if config.attack_enabled else None,
        forecast_curve=forecaster.history,
        forecast_error=forecast_error,
        flare_alerts=flare.alerts,
        probe_alerts=early.alerts,
        scores=flare.scores,
    )


def false_positive_rate(benign_df: pd.DataFrame, config: SimConfig) -> Dict[str, float]:
    """Fraction of attack-free windows on which each detector falsely fires."""
    feats = feature_columns()
    results = {}
    for name, det in [
        ("baseline", BaselineDetector()),
        ("flare", FlareDetector(features=feats)),
        ("early_warning", EarlyWarningDetector()),
    ]:
        fp = 0
        total = 0
        for run_id, g in benign_df.groupby("run_id"):
            # Fresh detector per run.
            if name == "baseline":
                d = BaselineDetector()
            elif name == "flare":
                d = FlareDetector(features=feats)
            else:
                d = EarlyWarningDetector()
            for _, r in g.iterrows():
                if float(r["t"]) < config.transient_skip:
                    continue
                row = {f: float(r[f]) for f in feats + ["occupancy"]}
                a = d.update(float(r["t"]), row)
                fp += 1 if a is not None else 0
                total += 1
        results[name] = fp / max(total, 1)
    return results


def compare_methods(df: pd.DataFrame, config: SimConfig,
                    benign_df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
    """Produce a tidy comparison table for a single scenario."""
    res = evaluate(df, config)
    rows = [
        {"method": "FloRa-style baseline", "detection_t": res.baseline_t,
         "lead_vs_overflow_s": (res.overflow_t - res.baseline_t)
         if res.baseline_t and res.overflow_t else None,
         "detects_probing": False},
        {"method": "FLARE (core)", "detection_t": res.flare_t,
         "lead_vs_overflow_s": res.lead_vs_overflow(), "detects_probing": False},
        {"method": "FLARE (early-warning)", "detection_t": res.probe_t,
         "lead_vs_overflow_s": res.earliest_lead_vs_overflow(),
         "detects_probing": res.probe_t is not None},
    ]
    table = pd.DataFrame(rows)
    table.attrs["overflow_t"] = res.overflow_t
    table.attrs["forecast_error_s"] = res.forecast_error
    if benign_df is not None:
        table.attrs["false_positive_rate"] = false_positive_rate(benign_df, config)
    return table
