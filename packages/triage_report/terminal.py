"""Plain-text terminal summary. Pure stdlib, no rich dependency, so it runs anywhere."""
from __future__ import annotations

from typing import List

from triage_core import Verdict

_TIER = {"fix_now": "FIX NOW", "fix_cycle": "FIX CYCLE", "monitor": "MONITOR"}


def _usd(n: float) -> str:
    if n >= 1_000_000:
        return f"${n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n/1_000:.0f}K"
    return f"${n:.0f}"


def terminal_summary(verdicts: List[Verdict]) -> str:
    counts = {"fix_now": 0, "fix_cycle": 0, "monitor": 0}
    for v in verdicts:
        counts[v.tier] += 1
    total = len(verdicts)
    act = counts["fix_now"] + counts["fix_cycle"]

    lines = []
    lines.append("")
    lines.append("  Exploit-Aware Vulnerability Triage")
    lines.append("  " + "=" * 58)
    lines.append(
        f"  {total} findings ingested  ->  {act} require a decision  "
        f"({counts['fix_now']} FIX NOW, {counts['fix_cycle']} this cycle)"
    )
    noise = counts["monitor"]
    if total:
        cut = 100 * noise // total
        lines.append(f"  {noise} deprioritized as noise ({cut}% of the list)")
    lines.append("  " + "-" * 58)
    lines.append(f"  {'TIER':<10}{'CVE':<18}{'EPSS':>6}{'KEV':>5}{'CVSS':>6}  ASSET")
    lines.append("  " + "-" * 58)
    for v in verdicts:
        e = v.enriched
        if v.tier == "monitor":
            continue
        lines.append(
            f"  {_TIER[v.tier]:<10}{v.cve:<18}"
            f"{e.epss*100:>5.0f}%{'yes' if e.kev else '-':>5}"
            f"{e.finding.cvss:>6.1f}  {v.asset.name}"
        )
    lines.append("  " + "-" * 58)
    top = next((v for v in verdicts if v.tier == "fix_now"), None)
    if top:
        lines.append(
            f"  Top exposure {top.cve}: expected loss "
            f"{_usd(top.expected_loss_low)}-{_usd(top.expected_loss_high)}, "
            f"fix within {top.deadline_days} days."
        )
    lines.append("")
    return "\n".join(lines)
