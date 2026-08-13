"""Core data models for the triage pipeline.

The pipeline is deterministic: identical inputs must produce identical
verdicts, so nothing here carries wall-clock state or randomness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# Illustrative impact ranges (USD) used only when the customer supplies no
# asset business value. They are placeholders for a real CRQ input, never a
# claim of precision. The board memo says so explicitly.
IMPACT_BY_CRITICALITY = {
    "critical": (500_000, 5_000_000),
    "high": (100_000, 1_000_000),
    "medium": (20_000, 200_000),
    "low": (5_000, 50_000),
}


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
    business_value_usd: float = 0.0    # 0 => fall back to IMPACT_BY_CRITICALITY


@dataclass(frozen=True)
class Enriched:
    """A finding decorated with real-world exploitation intelligence."""
    finding: Finding
    kev: bool = False          # present in CISA Known Exploited Vulnerabilities
    kev_date: str = ""
    epss: float = 0.0          # FIRST EPSS 30-day exploitation probability
    epss_date: str = ""
    exploit_available: bool = False


@dataclass
class Verdict:
    """The decision. This is the product: a scanner gives a list, we give this."""
    enriched: Enriched
    asset: Asset
    tier: str                                  # fix_now | fix_cycle | monitor
    score: float                               # ordering key, higher = sooner
    deadline_days: int
    reasons: List[str] = field(default_factory=list)
    attack_path: List[tuple] = field(default_factory=list)
    expected_loss_low: float = 0.0
    expected_loss_high: float = 0.0

    @property
    def cve(self) -> str:
        return self.enriched.finding.cve
