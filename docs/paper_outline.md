# FLARE — IEEE Paper Outline

**Title:** FLARE: Early, Adaptive, and Explainable Detection of Low-Rate
Flow-Table Overflow Attacks in Software-Defined Networks

**Target:** IEEE conference (e.g. IEEE ICC / GLOBECOM / NOMS / CNS).

---

## Abstract
Software-defined network switches store forwarding rules in a small, expensive
TCAM flow table. Low-Rate Flow-Table Overflow (LOFT) attacks exhaust this table
with minimal traffic, evading volume-based defenses. State-of-the-art detectors
(e.g. FloRa) react only once the table is already filling. We present **FLARE**,
which (i) raises an *early warning* during the attacker's probing phase, (ii)
*adapts online* to benign traffic drift, (iii) *forecasts* a time-to-overflow,
and (iv) *explains* each alert. On a realistic, reproducible SDN simulation FLARE
detects the attack ~125 s earlier than a FloRa-style baseline and ~150 s before
the table overflows, forecasts the overflow time to within ~14 s, and produces
no false positives on attack-free traffic.

## 1. Introduction
- SDN flow tables: small, expensive, security-critical resource.
- LOFT threat model: low-rate, stealthy, evades volume-based defenses.
- Limitation of prior art: reactive — fires only after the table fills.
- Contributions: early warning, online adaptation, forecasting, explainability.
- Reproducibility: open Colab notebook + dataset + code.

## 2. Background & Related Work
- SDN data plane, OpenFlow flow tables, idle/hard timeouts, TCAM limits.
- Flow-table overflow / saturation attacks; rate-based vs low-rate variants.
- FloRa (IEEE 2024) and other reactive detectors — what they miss.
- Online anomaly detection, CUSUM change detection, explainable security ML.

## 3. Threat Model
- Attacker capability: can install low-rate flows, observe coarse switch behavior.
- **Probing phase:** short-lived recon flows to measure the idle timeout.
- **Attack phase:** persistent flows refreshed just before timeout (never expire).
- Goal: fill the table so legitimate flows cannot be installed.
- Maps to `flare/config.py` (`probe_*`, `attack_*`) and `flare/simulator.py`.

## 4. The FLARE Framework
### 4.1 SDN switch & traffic model (§ `simulator.py`)
- Flow-table dynamics, install/refresh/expire, overflow drops.
- Benign traffic model; per-window feature extraction.
- Feature set: occupancy ratio, growth, miss/install/expiry/short-lived rates,
  net accumulation, packets-per-flow.
### 4.2 Core detector — online + adaptive (§ `detectors.FlareDetector`)
- CUSUM drift on flow-table growth (motivation: low-rate persistent fill).
- Directional z-scores on churn features; RMS aggregation; k-of-n persistence.
- Online EWMA baselines, frozen during alarms to resist poisoning.
### 4.3 Early-warning detector (§ `detectors.EarlyWarningDetector`)
- Probing signature: short-lived-flow / miss-rate anomaly with flat occupancy.
### 4.4 Time-to-overflow forecaster (§ `detectors.OverflowForecaster`)
- Sliding-window robust linear projection to capacity.
### 4.5 Explainability (§ `detectors.AlertExplainer`)
- Rank dominant anomalous features → plain-language reason.
### 4.6 Mitigation (§ `mitigation.py`)
- Selective eviction of low-activity flows + idle-timeout hardening.

## 5. Experimental Setup
- Simulator parameters (Table: capacity, idle timeout, rates, seeds).
- Baseline: FloRa-style occupancy-threshold detector.
- Dataset: multi-run, multi-intensity labeled windows (`dataset.py`).
- Metrics: detection time, lead vs overflow, lead vs baseline, FPR, forecast MAE.

## 6. Results
- **Fig 1** baseline LOFT attack overflows an undefended switch.
- **Fig 2** detection timeline — FLARE vs baseline lead time.
- **Fig 3** time-to-overflow forecast convergence.
- **Fig 4** mitigation keeps occupancy bounded.
- Table: per-method detection time / lead / probing-detection.
- Sensitivity: attack rate sweep; lead-time vs intensity.
- False-positive analysis on attack-free traffic.

## 7. Discussion
- Why CUSUM beats single-window scoring for low-rate attacks.
- Adaptivity vs attack-poisoning trade-off (freeze-on-alarm).
- Lead time → actionable operator response.
- Limitations: simulation vs hardware; single-switch scope.

## 8. Threats to Validity & Future Work
- Real testbed (Mininet / P4 / hardware) validation.
- Multi-switch / controller-wide correlation.
- Adversarial evasion (slower probing, mimicry).

## 9. Conclusion
FLARE turns flow-table overflow defense from reactive to *anticipatory*:
earlier, adaptive, forecasted, and explainable, with a fully reproducible
artifact.

---

### Claim → experiment traceability
| Paper claim | Code | Figure / metric |
|-------------|------|-----------------|
| Attack overflows undefended switch | `simulator.py` | Fig 1, `test_attack_overflows_without_defense` |
| Earlier than baseline | `evaluation.evaluate` | Fig 2, `flare_lead_vs_baseline_s` |
| Detects probing phase | `EarlyWarningDetector` | `probe_alert_t`, `test_early_warning_fires_in_probe_phase` |
| Forecasts overflow | `OverflowForecaster` | Fig 3, `forecast_error_s` |
| Adapts online, low FPR | `FlareDetector` | `false_positive_rate`, `test_false_positive_rate_is_low` |
| Explains alerts | `AlertExplainer` | alert `reason` strings |
| Mitigation bounds occupancy | `mitigation.py` | Fig 4 |
