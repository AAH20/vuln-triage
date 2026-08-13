"""Core data models for the triage pipeline.

The pipeline is deterministic: identical inputs must produce identical
verdicts, so nothing here carries wall-clock state or randomness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Finding:
    """One vulnerability as reported by any scanner, normalized."""
    cve: str
    package: str
    version: str
    source: str            # scanner that produced it (trivy, grype, ...)
    asset: str = "unknown"  # artifact / host the finding belongs to
    cvss: float = 0.0
    severity: str = ""     # scanner-reported severity label
    title: str = ""


@dataclass(frozen=True)
class Asset:
    """Business context for an asset. Supplied by the customer, never guessed."""
    name: str
    internet_facing: bool = False
    criticality: str = "medium"        # low | medium | high | critical
    loss_scenario_low_usd: Optional[float] = None
    loss_scenario_high_usd: Optional[float] = None
    loss_scenario_source: str = ""


@dataclass(frozen=True)
class Enriched:
    """A finding decorated with real-world exploitation intelligence."""
    finding: Finding
    kev: bool = False          # present in CISA Known Exploited Vulnerabilities
    kev_date: str = ""
    epss: Optional[float] = None
    epss_date: str = ""
    intelligence_mode: str = "unknown"
    intelligence_fresh: bool = False


@dataclass
class Verdict:
    """The decision. This is the product: a scanner gives a list, we give this."""
    enriched: Enriched
    asset: Asset
    tier: str                                  # fix_now | fix_cycle | monitor_candidate | unknown
    score: float                               # ordering key, higher = sooner
    deadline_days: int
    reasons: List[str] = field(default_factory=list)
    attack_path: List[tuple] = field(default_factory=list)
    loss_scenario_low: Optional[float] = None
    loss_scenario_high: Optional[float] = None

    @property
    def cve(self) -> str:
        return self.enriched.finding.cve
