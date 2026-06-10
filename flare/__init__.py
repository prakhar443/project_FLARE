"""FLARE: Early Detection of Low-Rate Flow-Table Overflow (LOFT) Attacks in SDN.

FLARE is a defensive framework that detects stealthy LOFT attacks against
software-defined-network switches *earlier* and more efficiently than prior
art (e.g. FloRa, IEEE 2024).  Its four contributions are:

1. Early warning   - it flags the attacker's quiet *probing* phase before the
                     flow table starts filling.
2. Online learning - it adapts to changing benign traffic on the fly, without
                     slow offline retraining.
3. Forecasting     - it predicts a *time-to-overflow*, giving operators an
                     actionable lead time instead of a fixed alarm.
4. Explainability  - every alert ships with a plain-language reason.

The package is fully self-contained (numpy / pandas / scikit-learn) so that the
entire pipeline reproduces inside a free Google Colab notebook.
"""

from .config import SimConfig, DEFAULT_CONFIG
from .simulator import SDNSimulator
from .dataset import generate_dataset, generate_benign_only
from .detectors import (
    BaselineDetector,
    FlareDetector,
    EarlyWarningDetector,
    OverflowForecaster,
    AlertExplainer,
)
from .mitigation import MitigationEngine
from .evaluation import evaluate, compare_methods

__all__ = [
    "SimConfig",
    "DEFAULT_CONFIG",
    "SDNSimulator",
    "generate_dataset",
    "generate_benign_only",
    "BaselineDetector",
    "FlareDetector",
    "EarlyWarningDetector",
    "OverflowForecaster",
    "AlertExplainer",
    "MitigationEngine",
    "evaluate",
    "compare_methods",
]

__version__ = "0.1.0"
