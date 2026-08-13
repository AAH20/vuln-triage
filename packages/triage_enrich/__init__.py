"""triage_enrich: decorate findings with real-world exploitation intelligence.

CISA KEV answers "is it actually being exploited?" (the single strongest
signal). FIRST EPSS answers "how likely in the next 30 days?". Bundled
samples let the tool run offline; --refresh pulls the live feeds.
"""
from __future__ import annotations

from typing import List

from triage_core import Enriched, Finding

from .epss import EpssTable
from .kev import KevTable


def enrich(findings: List[Finding], kev: KevTable, epss: EpssTable) -> List[Enriched]:
    out: List[Enriched] = []
    for f in findings:
        k = kev.get(f.cve)
        e = epss.get(f.cve)
        out.append(
            Enriched(
                finding=f,
                kev=k is not None,
                kev_date=k or "",
                epss=e[0] if e else 0.0,
                epss_date=e[1] if e else "",
                exploit_available=k is not None,  # KEV implies a working exploit
            )
        )
    return out


__all__ = ["enrich", "KevTable", "EpssTable"]
