"""Detectors used in FLARE and the baseline it is compared against.

* ``BaselineDetector``      - a FloRa-style reactive detector that only fires
                              once the flow table is already filling up.
* ``FlareDetector``         - FLARE's core *online, adaptive* anomaly detector.
* ``EarlyWarningDetector``  - flags the attacker's quiet probing phase.
* ``OverflowForecaster``    - predicts a time-to-overflow (actionable lead time).
* ``AlertExplainer``        - turns an alert into a plain-language reason.

Every detector is *streaming*: it consumes one window's feature row at a time
via ``update`` so the whole stack can run live, exactly as it would on a switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from .simulator import feature_columns


# --------------------------------------------------------------------------- #
# Online running statistics (the heart of "adapts on the fly")
# --------------------------------------------------------------------------- #
class _EWMAStats:
    """Exponentially-weighted running mean & variance for one feature.

    Adaptivity comes from only updating the model while traffic looks *normal*;
    when an anomaly is in progress we freeze the baseline so the attack does not
    poison the very statistics used to detect it.
    """

    def __init__(self, alpha: float = 0.02, warmup: int = 30):
        self.alpha = alpha
        self.warmup = warmup
        self.n = 0
        self.mean = 0.0
        self.var = 1e-6

    def ready(self) -> bool:
        return self.n >= self.warmup

    def z(self, x: float) -> float:
        # During warm-up the variance estimate is unreliable, so report no
        # anomaly rather than a spurious huge z-score.
        if not self.ready():
            return 0.0
        std = max(np.sqrt(self.var), 1e-6)
        return (x - self.mean) / std

    def update(self, x: float, learn: bool = True) -> None:
        self.n += 1
        if self.n <= self.warmup:
            # Plain incremental moments during warm-up for a stable start.
            delta = x - self.mean
            self.mean += delta / self.n
            self.var += (delta * (x - self.mean) - self.var) / self.n
            return
        if not learn:
            return
        delta = x - self.mean
        self.mean += self.alpha * delta
        self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)


class _CUSUM:
    """One-sided cumulative-sum drift detector.

    CUSUM is the natural tool for *low-rate* attacks: it integrates small,
    persistent positive deviations that a single-window z-score would miss,
    firing once the accumulated drift exceeds a limit.  The reference mean and
    spread are learned online from benign traffic.
    """

    def __init__(self, k_sigma: float = 1.0, h_sigma: float = 9.0,
                 alpha: float = 0.02, warmup: int = 30,
                 freeze_level: float = 0.5):
        self.stats = _EWMAStats(alpha=alpha, warmup=warmup)
        self.k_sigma = k_sigma
        self.h_sigma = h_sigma
        # Stop updating the reference once accumulated drift reaches this
        # fraction of the decision limit -- otherwise a slowly escalating
        # attack teaches the CUSUM that its own growth rate is normal.
        self.freeze_level = freeze_level
        self.s = 0.0

    def update(self, x: float, learn: bool = True) -> float:
        ready = self.stats.ready()
        mean = self.stats.mean
        std = max(np.sqrt(self.stats.var), 1e-6)
        k = self.k_sigma * std
        self.s = max(0.0, self.s + (x - mean - k))
        if not ready:
            self.s = 0.0  # do not accumulate drift during warm-up
            self.stats.update(x, learn=True)
            return 0.0
        # Normalised drift: >=1 means the CUSUM limit has been crossed.
        drift = self.s / (self.h_sigma * std)
        # Self-gated freeze-on-alarm: learn the reference only while the
        # statistic itself shows no meaningful accumulation.
        if learn and drift < self.freeze_level:
            self.stats.update(x, learn=True)
        return drift


# Per-feature direction: +1 => high values are anomalous, -1 => low values are.
FLARE_FEATURES = {
    "miss_rate": +1,
    "short_lived_rate": +1,
    "install_rate": +1,
    "expiry_rate": +1,
    "pps_per_flow": -1,   # LOFT flows carry suspiciously little traffic each
}
# The drift signal: sustained positive growth of the table is the smoking gun.
FLARE_DRIFT_FEATURE = "occ_growth_ewma"


@dataclass
class Alert:
    t: float
    score: float
    reason: str = ""
    kind: str = "attack"


# --------------------------------------------------------------------------- #
# Baseline: FloRa-style reactive occupancy detector
# --------------------------------------------------------------------------- #
class BaselineDetector:
    """Reactive baseline: alert when occupancy crosses a fixed fraction of the
    table capacity.  This mirrors prior art (FloRa-style) that responds only
    once the table has *already* started filling up, leaving little lead time."""

    def __init__(self, occ_threshold: float = 0.80):
        self.occ_threshold = occ_threshold
        self.alerts: List[Alert] = []
        self.first_alert: Optional[float] = None

    def update(self, t: float, row: Dict[str, float]) -> Optional[Alert]:
        fired = row["occupancy_ratio"] >= self.occ_threshold
        if fired:
            a = Alert(t=t, score=row["occupancy_ratio"],
                      reason=f"occupancy {row['occupancy_ratio']:.0%} of capacity",
                      kind="attack")
            self.alerts.append(a)
            if self.first_alert is None:
                self.first_alert = t
            return a
        return None


# --------------------------------------------------------------------------- #
# FLARE core: online multivariate anomaly detector
# --------------------------------------------------------------------------- #
class FlareDetector:
    """Streaming, self-adapting anomaly detector -- FLARE's core.

    Two complementary signals, both with online baselines that adapt to benign
    traffic on the fly:

    * a **CUSUM drift detector** on flow-table growth, which integrates the
      small but *persistent* accumulation that defines a low-rate overflow
      attack (and which a single-window z-score adapts away), and
    * **directional z-scores** on flow-churn features (miss/install/expiry
      rate, traffic-per-flow), which catch the sharper signatures.

    Learning is frozen while an anomaly is in progress so the attack cannot
    poison the very baseline used to detect it.  Persistence (k-of-n) suppresses
    single-window false positives.
    """

    def __init__(self, features: Optional[List[str]] = None,
                 alpha: float = 0.02, warmup: int = 30,
                 score_threshold: float = 3.0, persistence: int = 3,
                 window_n: int = 5):
        self.features = list(FLARE_FEATURES.keys())
        self.directions = FLARE_FEATURES
        self.stats = {f: _EWMAStats(alpha=alpha, warmup=warmup) for f in self.features}
        self.cusum = _CUSUM(alpha=alpha, warmup=warmup)
        self.score_threshold = score_threshold
        self.persistence = persistence
        self.window_n = window_n
        self.warmup = warmup
        self._seen = 0
        self._recent: List[bool] = []
        self.alerts: List[Alert] = []
        self.first_alert: Optional[float] = None
        self.scores: List[float] = []
        self.last_z: Dict[str, float] = {}

    def _anomaly_z(self, row: Dict[str, float]) -> Dict[str, float]:
        z = {}
        for f, direction in self.directions.items():
            zi = direction * self.stats[f].z(float(row[f]))
            z[f] = max(zi, 0.0)  # only count deviations in the suspicious dir.
        return z

    def update(self, t: float, row: Dict[str, float]) -> Optional[Alert]:
        self._seen += 1
        z = self._anomaly_z(row)

        # RMS of churn z-scores: a sharp, multi-feature anomaly score.
        z_score = float(np.sqrt(np.mean(np.square(list(z.values())))))
        anomalous_now = z_score >= self.score_threshold

        # CUSUM drift: peek without learning to decide if we are drifting.
        drift = self.cusum.update(float(row[FLARE_DRIFT_FEATURE]),
                                  learn=not anomalous_now)
        drifting = drift >= 1.0

        # Combined score (for plotting): churn anomaly OR drift, on one scale.
        score = max(z_score, drift * self.score_threshold)
        self.scores.append(score)
        z_with_drift = dict(z)
        z_with_drift[FLARE_DRIFT_FEATURE] = drift * self.score_threshold
        self.last_z = z_with_drift

        anomalous = anomalous_now or drifting
        self._recent.append(anomalous)
        if len(self._recent) > self.window_n:
            self._recent.pop(0)
        confirmed = sum(self._recent) >= self.persistence

        # Freeze the churn baselines while alarming; otherwise adapt online.
        learn = not anomalous
        for f in self.features:
            self.stats[f].update(float(row[f]), learn=learn)

        # Suppress alerts until the adaptive baseline has stabilised.
        if confirmed and self._seen > self.warmup:
            reason = AlertExplainer.explain(z_with_drift)
            a = Alert(t=t, score=score, reason=reason, kind="attack")
            self.alerts.append(a)
            if self.first_alert is None:
                self.first_alert = t
            return a
        return None


# --------------------------------------------------------------------------- #
# Early warning: detect the quiet probing phase
# --------------------------------------------------------------------------- #
class EarlyWarningDetector:
    """Spot the attacker's reconnaissance *before* the table fills.

    The probing phase shows up as a sustained excess of short-lived, single
    packet churn (the attacker measuring the idle timeout) that is *not* yet
    accompanied by occupancy growth.  We watch the ``short_lived_rate`` and
    ``miss_rate`` signatures with their own adaptive baselines.
    """

    def __init__(self, alpha: float = 0.02, warmup: int = 30,
                 z_threshold: float = 2.8, persistence: int = 3, window_n: int = 5):
        self.signals = ["short_lived_rate", "miss_rate"]
        self.stats = {s: _EWMAStats(alpha=alpha, warmup=warmup) for s in self.signals}
        self.z_threshold = z_threshold
        self.persistence = persistence
        self.window_n = window_n
        self.warmup = warmup
        self._seen = 0
        self._recent: List[bool] = []
        self.alerts: List[Alert] = []
        self.first_alert: Optional[float] = None

    def update(self, t: float, row: Dict[str, float]) -> Optional[Alert]:
        self._seen += 1
        zs = {s: max(self.stats[s].z(float(row[s])), 0.0) for s in self.signals}
        # Probing = churn anomaly while occupancy is still low/flat.
        churn_anomaly = max(zs.values()) >= self.z_threshold
        not_yet_full = row["occupancy_ratio"] < 0.6
        flag = churn_anomaly and not_yet_full

        learn = not churn_anomaly
        for s in self.signals:
            self.stats[s].update(float(row[s]), learn=learn)

        self._recent.append(flag)
        if len(self._recent) > self.window_n:
            self._recent.pop(0)
        if sum(self._recent) >= self.persistence and self._seen > self.warmup:
            lead = ", ".join(f"{s}=+{zs[s]:.1f}σ" for s in self.signals)
            a = Alert(t=t, score=max(zs.values()),
                      reason=f"probing-phase churn ({lead}) without occupancy rise",
                      kind="probe")
            self.alerts.append(a)
            if self.first_alert is None:
                self.first_alert = t
            return a
        return None


# --------------------------------------------------------------------------- #
# Forecasting: time-to-overflow
# --------------------------------------------------------------------------- #
class OverflowForecaster:
    """Predict seconds-until-overflow from the recent occupancy trend.

    A least-squares line is fit over a sliding window of recent occupancy. To
    avoid the wild, jittery extrapolations that a flat-but-noisy benign signal
    would otherwise produce, a forecast is emitted *only* once the table is
    genuinely, persistently filling -- i.e. the fitted slope is clearly positive
    (``min_slope``) **and** the fit is a good one (``r2_min``) for several
    consecutive windows (``confirm``).  The result is a clean ETA that appears
    only when there is something to forecast and then converges on the truth.
    """

    def __init__(self, capacity: int, window_s: int = 20, min_slope: float = 3.0,
                 r2_min: float = 0.7, confirm: int = 10):
        self.capacity = capacity
        self.window_s = window_s
        self.min_slope = min_slope
        self.r2_min = r2_min
        self.confirm = confirm
        self._t: List[float] = []
        self._occ: List[float] = []
        self._streak = 0
        self.history: List[tuple] = []  # (t, eta, slope)

    def update(self, t: float, occupancy: float) -> Optional[float]:
        self._t.append(t)
        self._occ.append(occupancy)
        if len(self._t) > self.window_s:
            self._t.pop(0)
            self._occ.pop(0)
        if len(self._t) < max(5, self.window_s // 2):
            self.history.append((t, None, 0.0))
            return None

        ts = np.array(self._t)
        occ = np.array(self._occ)
        slope, intercept = np.polyfit(ts, occ, 1)
        # Goodness of fit: a flat, noisy benign window has a near-zero R^2,
        # whereas a real fill is close to linear (R^2 -> 1).
        fit = intercept + slope * ts
        ss_res = float(np.sum((occ - fit) ** 2))
        ss_tot = float(np.sum((occ - occ.mean()) ** 2)) + 1e-9
        r2 = 1.0 - ss_res / ss_tot

        sustained = slope >= self.min_slope and r2 >= self.r2_min
        self._streak = self._streak + 1 if sustained else 0
        if self._streak < self.confirm:
            self.history.append((t, None, slope))
            return None

        current = intercept + slope * t
        eta = max((self.capacity - current) / slope, 0.0)
        self.history.append((t, eta, slope))
        return float(eta)


# --------------------------------------------------------------------------- #
# Explainability
# --------------------------------------------------------------------------- #
_FEATURE_PHRASES = {
    "occupancy_ratio": "flow table unusually full",
    "occ_growth_ewma": "flow table filling faster than normal",
    "miss_rate": "surge of table-miss / new-flow events",
    "short_lived_rate": "burst of short-lived probe-like flows",
    "expiry_rate": "abnormal entry-expiry rate",
    "install_rate": "elevated rule-installation rate",
    "net_accumulation_ewma": "entries accumulating faster than they expire",
    "pps_per_flow": "flows carrying suspiciously little traffic each",
}


class AlertExplainer:
    """Render the dominant anomalous features as a human-readable reason."""

    @staticmethod
    def explain(z: Dict[str, float], top_k: int = 2) -> str:
        ranked = sorted(z.items(), key=lambda kv: kv[1], reverse=True)
        parts = []
        for f, zi in ranked[:top_k]:
            if zi <= 0:
                continue
            phrase = _FEATURE_PHRASES.get(f, f)
            parts.append(f"{phrase} (+{zi:.1f}σ)")
        return "; ".join(parts) if parts else "anomalous flow-table dynamics"
