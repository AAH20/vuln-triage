"""Markdown treatment register: the evidence-backed, per-finding decision list."""
from __future__ import annotations

from typing import List

from triage_core import Verdict

_TIER = {"fix_now": "FIX NOW", "fix_cycle": "FIX THIS CYCLE", "monitor_candidate": "MONITOR CANDIDATE", "unknown": "UNKNOWN"}


def _usd(n: float) -> str:
    if n >= 1_000_000:
        return f"${n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n/1_000:.0f}K"
    return f"${n:.0f}"


def treatment_register(verdicts: List[Verdict]) -> str:
    out = ["# Treatment Register", "", "_Prioritized by real-world exploitation, not CVSS alone._", ""]
    for tier in ("fix_now", "fix_cycle", "monitor_candidate", "unknown"):
        group = [v for v in verdicts if v.tier == tier]
        if not group:
            continue
        out.append(f"## {_TIER[tier]} ({len(group)})")
        out.append("")
        for v in group:
            e = v.enriched
            out.append(f"### {v.cve} on `{v.asset.name}`")
            out.append("")
            out.append(f"- Package: `{e.finding.package} {e.finding.version}` (via {e.finding.source})")
            out.append(f"- CISA KEV: {'YES, cataloged since ' + e.kev_date if e.kev else 'no match in supplied catalog'}")
            out.append(f"- EPSS: {e.epss:.1%} 30-day exploitation probability" + (f" ({e.epss_date})" if e.epss_date else "") if e.epss is not None else "- EPSS: unknown")
            out.append(f"- Intelligence provenance: {e.intelligence_mode}; live-fresh={str(e.intelligence_fresh).lower()}")
            out.append(f"- CVSS: {e.finding.cvss:g}")
            out.append(f"- Reachability: {'internet-facing' if v.asset.internet_facing else 'internal / segmented'}")
            out.append(f"- Asset criticality: {v.asset.criticality}")
            out.append(f"- Decision: **{_TIER[tier]}**" + (f", within {v.deadline_days} days" if v.deadline_days else ""))
            out.append(f"- Rationale: {'; '.join(v.reasons)}")
            if v.attack_path:
                chain = " -> ".join(f"{t} {name}" for t, name in v.attack_path)
                out.append(f"- Plausible attack path (narrative, not executed): {chain}")
            if v.loss_scenario_low is not None and v.loss_scenario_high is not None:
                out.append(
                    f"- Customer-supplied loss scenario: {_usd(v.loss_scenario_low)}-"
                    f"{_usd(v.loss_scenario_high)} ({v.asset.loss_scenario_source or 'source not supplied'})"
                )
            out.append("")
    return "\n".join(out)
