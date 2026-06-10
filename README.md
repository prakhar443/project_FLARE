# FLARE

### Early Detection of Low-Rate Flow-Table Overflow (LOFT) Attacks in Software-Defined Networks

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/prakhar443/project_flare/blob/claude/affectionate-archimedes-rjk02/notebooks/FLARE_Colab.ipynb)

FLARE is a defensive framework that detects stealthy **Low-Rate Flow-Table
Overflow (LOFT)** attacks against SDN switches **earlier and more efficiently**
than prior art (e.g. *FloRa*, IEEE 2024). The entire pipeline — a realistic SDN
switch + traffic simulator, the detector stack, the evaluation, and all figures —
reproduces end-to-end on a free **Google Colab** notebook, with no special
hardware.

---

## The problem

Each SDN switch stores forwarding rules in a small, expensive TCAM "flow table"
holding only a few thousand entries. A **LOFT attack** quietly installs
long-lived, *low-rate* malicious flows — each refreshed just before the idle
timeout so its entry never expires — slowly filling the table with almost no
traffic. It stays under the radar of volume-based defenses until legitimate
flows can no longer be installed and the network degrades.

## What makes FLARE novel

The closest published work only *reacts* once the table is already filling up.
FLARE adds four concrete capabilities:

| # | Capability | How FLARE does it |
|---|------------|-------------------|
| 1 | **Early warning** | An `EarlyWarningDetector` flags the attacker's quiet **probing phase** (a burst of short-lived recon flows) *before* occupancy rises. |
| 2 | **Adapts on the fly** | Online EWMA baselines + CUSUM learn continuously and freeze during alarms, so the model tracks changing benign traffic **without offline retraining**. |
| 3 | **Forecasts the risk** | An `OverflowForecaster` projects the occupancy trend to a **time-to-overflow** ETA — an actionable lead time, not a fixed alarm. |
| 4 | **Explains its alerts** | Every alert ships with a plain-language reason naming the dominant anomalous features (`AlertExplainer`). |

## Headline result (default scenario, seed 7)

| Method | Detection time | Lead before overflow | Detects probing? |
|--------|---------------:|---------------------:|:----------------:|
| FloRa-style baseline | 336 s | **25 s** | ✗ |
| **FLARE (core)** | 211 s | **150 s** | ✗ |
| **FLARE (early-warning)** | 210 s | **151 s** | ✓ |

- Table overflows at **361 s**; FLARE warns **~125 s earlier** than the baseline.
- **Time-to-overflow forecast error: ~14 s.**
- **False-positive rate on attack-free traffic: 0%** for every detector.

![detection timeline](figures/02_detection_timeline.png)
![mitigation](figures/04_mitigation.png)

---

## Quick start

### Run on Google Colab (one click)
Open [`notebooks/FLARE_Colab.ipynb`](notebooks/FLARE_Colab.ipynb) via the badge
above and run all cells. It clones the repo, runs the full pipeline, and renders
every figure inline.

### Run locally
```bash
pip install -r requirements.txt

# Reproduce all results + figures into ./figures
python scripts/run_experiments.py

# Run the test suite (verifies FLARE's core claims)
pytest -q
```

### Use the library
```python
from flare import SimConfig, SDNSimulator, evaluate, compare_methods

cfg = SimConfig(seed=7)
df  = SDNSimulator(cfg).run()          # per-window features + labels
res = evaluate(df, cfg)                # stream through every detector
print(res.summary())
print(compare_methods(df, cfg))
```

---

## How it works

```
flare/
├── config.py        SimConfig — switch, traffic and attack parameters
├── simulator.py     packet-level SDN switch + flow-table model + traffic
│                    generator (benign, probing, low-rate attack)
├── detectors.py     BaselineDetector (FloRa-style), FlareDetector (CUSUM +
│                    directional z-scores), EarlyWarningDetector,
│                    OverflowForecaster, AlertExplainer
├── mitigation.py    selective eviction + idle-timeout hardening
├── dataset.py       labeled multi-run dataset generation
└── evaluation.py    detection times, lead-time, FPR, forecast error
```

**Simulator.** A flow table of `capacity` entries with an `idle_timeout`. Entries
are installed on a flow's first packet and refreshed on each match; they expire
`idle_timeout` seconds after the last match. When the table is full, new installs
fail (overflow drops). Benign traffic is Poisson flow arrivals with exponential
lifetimes; the LOFT attacker adds a short **probing** phase followed by
persistent **low-rate** flows refreshed just before the timeout.

**Detection.** FLARE combines a **CUSUM** drift detector on flow-table growth
(the right tool for slow, persistent, low-rate fills that a single-window
z-score adapts away) with **directional z-scores** on flow-churn features. All
baselines adapt online and freeze while alarming so the attack cannot poison
them. A separate early-warning detector watches the short-lived-flow / miss-rate
churn signature of the probing phase while occupancy is still low.

**Forecasting.** A sliding-window linear fit of recent occupancy projects when
capacity will be reached, giving operators a converging ETA.

See [`docs/paper_outline.md`](docs/paper_outline.md) for the IEEE paper structure
mapping each contribution to its experiment.

## Reproducibility

Everything is seeded (`SimConfig.seed`). `scripts/run_experiments.py` writes the
labeled dataset, a machine-readable `results_summary.csv`, and all four figures.
`pytest` asserts the core claims (table overflows without defense; FLARE detects
earlier than the baseline; early-warning fires in the probing phase; low FPR).

## License

MIT — see [LICENSE](LICENSE).
