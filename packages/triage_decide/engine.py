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

from triage_core import IMPACT_BY_CRITICALITY, Asset, Enriched, Verdict

from .attack import narrative

EPSS_CYCLE_THRESHOLD = 0.10


def _expected_loss(e: Enriched, asset: Asset) -> tuple:
    if asset.business_value_usd > 0:
        impact_low = asset.business_value_usd * 0.10
        impact_high = asset.business_value_usd
    else:
        impact_low, impact_high = IMPACT_BY_CRITICALITY.get(
            asset.criticality, IMPACT_BY_CRITICALITY["medium"]
        )

    if e.kev:
        like_low, like_high = 0.30, 0.70
    elif e.epss >= EPSS_CYCLE_THRESHOLD:
        like_low, like_high = 0.10, max(EPSS_CYCLE_THRESHOLD, e.epss)
    else:
        like_low, like_high = 0.001, max(0.02, e.epss)

    if asset.internet_facing:
        like_high = min(0.90, like_high * 1.5)

    return round(like_low * impact_low), round(like_high * impact_high)


def decide(e: Enriched, asset: Asset) -> Verdict:
    reachable = asset.internet_facing
    critical = asset.criticality in ("high", "critical")
    reasons: List[str] = []

    if e.kev and (reachable or critical):
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
        tier, deadline = "monitor", 0
        reasons.append("No confirmed exploitation and low 30-day probability")
        if e.finding.cvss >= 7.0:
            reasons.append(
                f"CVSS {e.finding.cvss:g} would label this Critical/High, "
                "but real-world risk is low: deprioritized"
            )

    # Ordering score. KEV dominates; EPSS, reachability, criticality, then CVSS.
    score = (
        (1000 if e.kev else 0)
        + e.epss * 300
        + (150 if reachable else 0)
        + (80 if critical else 0)
        + e.finding.cvss
    )

    lo, hi = _expected_loss(e, asset)
    return Verdict(
        enriched=e,
        asset=asset,
        tier=tier,
        score=round(score, 3),
        deadline_days=deadline,
        reasons=reasons,
        attack_path=narrative(reachable) if tier != "monitor" else [],
        expected_loss_low=lo,
        expected_loss_high=hi,
    )


def decide_all(enriched: List[Enriched], assets: dict, default: Asset) -> List[Verdict]:
    verdicts = [decide(e, assets.get(e.finding.asset, default)) for e in enriched]
    verdicts.sort(key=lambda v: v.score, reverse=True)
    return verdicts
