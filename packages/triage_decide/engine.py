"""The three-tier decision engine.

Priority is not CVSS. CVSS is technical severity in the abstract; FIRST and
CISA both say do not prioritize on it alone. We combine:

  KEV          actually exploited in the wild        (strongest signal)
  EPSS         30-day exploitation probability
  reachability internet-facing or segmented          (environmental)
  criticality  business importance of the asset      (environmental)

Tiers:
  fix_now    KEV AND (reachable OR business-critical)      deadline 7d
  fix_cycle  KEV, or EPSS >= 0.10                          deadline 30d
  monitor    everything else                              no deadline

The expected-loss range is a CRQ *scaffold*: measured likelihood times a
customer-supplied (or placeholder) impact. It is a range, never a fake
precise figure. Full CRQ is the paid engagement.
"""
from __future__ import annotations

from typing import List

from triage_core import Asset, Enriched, Verdict

from .attack import narrative

EPSS_CYCLE_THRESHOLD = 0.10


def decide(e: Enriched, asset: Asset) -> Verdict:
    reachable = asset.internet_facing
    critical = asset.criticality in ("high", "critical")
    reasons: List[str] = []

    if e.intelligence_mode == "sample" or e.epss is None:
        tier, deadline = "unknown", 0
        reasons.append("Insufficient production intelligence; sample or missing EPSS evidence")
    elif e.kev and (reachable or critical):
        tier, deadline = "fix_now", 7
        reasons.append("Actively exploited in the wild (CISA KEV)")
        if reachable:
            reasons.append("Reachable from the internet")
        if critical:
            reasons.append(f"On a business-critical asset ({asset.criticality})")
    elif e.kev or e.epss >= EPSS_CYCLE_THRESHOLD:
        tier, deadline = "fix_cycle", 30
        if e.kev:
            reasons.append("In CISA KEV, but not currently reachable or critical")
        if e.epss >= EPSS_CYCLE_THRESHOLD:
            reasons.append(f"High 30-day exploitation probability (EPSS {e.epss:.0%})")
    else:
        tier, deadline = "monitor_candidate", 0
        reasons.append("No KEV match in the supplied catalog and comparatively low EPSS probability")
        if e.finding.cvss >= 7.0:
            reasons.append(
                f"CVSS {e.finding.cvss:g} would label this Critical/High, "
                "but current threat-intelligence priority is lower; environmental validation remains required"
            )

    # Ordering score. KEV dominates; EPSS, reachability, criticality, then CVSS.
    score = (
        (1000 if e.kev else 0)
        + (e.epss or 0) * 300
        + (150 if reachable else 0)
        + (80 if critical else 0)
        + e.finding.cvss
    )

    return Verdict(
        enriched=e,
        asset=asset,
        tier=tier,
        score=round(score, 3),
        deadline_days=deadline,
        reasons=reasons,
        attack_path=narrative(reachable) if tier in ("fix_now", "fix_cycle") else [],
        loss_scenario_low=asset.loss_scenario_low_usd,
        loss_scenario_high=asset.loss_scenario_high_usd,
    )


def decide_all(enriched: List[Enriched], assets: dict, default: Asset) -> List[Verdict]:
    verdicts = [decide(e, assets.get(e.finding.asset, default)) for e in enriched]
    verdicts.sort(key=lambda v: v.score, reverse=True)
    return verdicts
