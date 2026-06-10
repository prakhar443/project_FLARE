"""Configuration for the FLARE SDN simulation and LOFT attack scenario.

All timings are in seconds.  The defaults are chosen so that, with no defense,
a stealthy LOFT attack overflows the flow table roughly two minutes after the
attack phase begins -- giving plenty of room to demonstrate FLARE's lead time.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class SimConfig:
    # ----- Switch / flow-table model -------------------------------------
    capacity: int = 1500          # max flow-table entries (small, expensive TCAM)
    idle_timeout: float = 10.0    # entry evicted after this many seconds of no match

    # ----- Simulation clock ----------------------------------------------
    duration: float = 600.0       # total simulated seconds
    window: float = 1.0           # feature-extraction window (seconds)
    transient_skip: float = 30.0  # ignore the empty-table fill-up transient
    seed: int = 7

    # ----- Benign traffic -------------------------------------------------
    benign_flow_rate: float = 26.0   # new benign flows per second (Poisson)
    benign_mean_duration: float = 8.0  # mean benign flow lifetime (exponential)
    benign_pps: float = 3.0          # packets/sec inside an active benign flow
    benign_short_frac: float = 0.12  # fraction of benign flows that are 1-2 pkt blips

    # ----- LOFT attack scenario ------------------------------------------
    attack_enabled: bool = True
    probe_start: float = 200.0    # attacker's quiet reconnaissance begins
    probe_duration: float = 40.0  # length of the probing phase
    probe_rate: float = 14.0      # probe flows per second (short-lived, low volume)

    attack_start: float = 240.0   # malicious low-rate flow installation begins
    attack_flow_rate: float = 9.0  # new malicious flows per second
    # each malicious flow is refreshed just before idle_timeout so its entry
    # never expires -- the essence of a "low-rate" overflow attack.
    attack_refresh_margin: float = 1.0

    def __post_init__(self) -> None:
        if self.attack_refresh_margin >= self.idle_timeout:
            raise ValueError("attack_refresh_margin must be < idle_timeout")
        if self.window <= 0:
            raise ValueError("window must be positive")

    @property
    def n_windows(self) -> int:
        return int(self.duration / self.window)

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_CONFIG = SimConfig()
