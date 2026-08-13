"""One-page executive decision memo. Translates the top exposures into the
language a board transacts in: what, why now, business consequence, what to
authorize, cost of delay, what remains uncertain.
"""
from __future__ import annotations

from typing import List

from triage_core import Verdict


def _usd(n: float) -> str:
    if n >= 1_000_000:
        return f"${n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n/1_000:.0f}K"
    return f"${n:.0f}"


def board_memo(verdicts: List[Verdict]) -> str:
    now = [v for v in verdicts if v.tier == "fix_now"]
    cycle = [v for v in verdicts if v.tier == "fix_cycle"]
    monitor = [v for v in verdicts if v.tier == "monitor"]
    total = len(verdicts)

    loss_low = sum(v.expected_loss_low for v in now)
    loss_high = sum(v.expected_loss_high for v in now)

    out = ["# Executive Exposure Decision Memo", ""]
    out.append(
        f"Of **{total}** vulnerabilities reported by scanning, **{len(now)}** demand "
        f"immediate authorization, **{len(cycle)}** should be scheduled this cycle, "
        f"and **{len(monitor)}** are low real-world risk and can be monitored. "
        "Prioritization uses confirmed exploitation (CISA KEV) and 30-day probability "
        "(FIRST EPSS), not CVSS severity alone."
    )
    out.append("")
    out.append("## What is exposed and why it matters now")
    out.append("")
    if now:
        for v in now:
            chain = " -> ".join(t for t, _ in v.attack_path)
            out.append(
                f"- **{v.cve}** on **{v.asset.name}** is being actively exploited in the wild, "
                f"is {'internet-facing' if v.asset.internet_facing else 'reachable'}, and sits on a "
                f"{v.asset.criticality} asset. A successful exploit follows a known path "
                f"({chain}) ending in business disruption. Expected loss if exploited: "
                f"**{_usd(v.expected_loss_low)}-{_usd(v.expected_loss_high)}**. "
                f"Authorize remediation within **{v.deadline_days} days**."
            )
    else:
        out.append("- No actively-exploited, reachable, critical exposures at this time.")
    out.append("")
    out.append("## What management should authorize")
    out.append("")
    out.append(
        f"- Immediate maintenance window for the {len(now)} FIX NOW items "
        f"(aggregate expected-loss exposure {_usd(loss_low)}-{_usd(loss_high)})."
    )
    out.append(f"- Scheduled remediation of the {len(cycle)} FIX THIS CYCLE items within 30 days.")
    out.append("- Documented risk acceptance for the monitored items, revisited if their exploitation signal changes.")
    out.append("")
    out.append("## What remains uncertain")
    out.append("")
    out.append(
        "- Expected-loss figures are a scaffold (measured likelihood times supplied or "
        "placeholder impact), not a calibrated CRQ. Supplying asset business values sharpens them."
    )
    out.append(
        "- Reachability reflects the asset context provided; unverified assets default to conservative assumptions."
    )
    out.append(
        "- Public exploitation activity does not by itself prove this organization is being targeted; "
        "confirming that requires authorized environment evidence."
    )
    out.append("")
    out.append("---")
    out.append(
        "_Prioritization: exploit-aware triage. Remediation engineering, authorized threat "
        "emulation and calibrated risk quantification are available as a follow-on engagement._"
    )
    return "\n".join(out)
