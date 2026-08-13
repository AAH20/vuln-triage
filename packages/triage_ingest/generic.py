"""Adapter for a plain CVE list (CSV/TXT) or a bare JSON array.

CSV columns (header optional): cve,package,version,asset,cvss,severity
A bare line is treated as a CVE id. This lets anyone pipe OpenVAS, Nmap NSE
(`--script vulners`), or a hand-written list into the engine.
"""
from __future__ import annotations

import csv
import io
import re
from typing import List

from triage_core import Finding

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def load(text: str) -> List[Finding]:
    findings: List[Finding] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        joined = ",".join(row)
        m = CVE_RE.search(joined)
        if not m:
            continue
        cve = m.group(0).upper()
        cols = [c.strip() for c in row]
        # header row?
        if cols[0].lower() in ("cve", "id", "vulnerability"):
            continue
        cvss = 0.0
        for c in cols:
            try:
                f = float(c)
                if 0 <= f <= 10:
                    cvss = f
                    break
            except ValueError:
                pass
        findings.append(
            Finding(
                cve=cve,
                package=cols[1] if len(cols) > 1 else "",
                version=cols[2] if len(cols) > 2 else "",
                source="generic",
                asset=cols[3] if len(cols) > 3 else "unknown",
                cvss=cvss,
            )
        )
    return findings


def load_json(arr: list) -> List[Finding]:
    out: List[Finding] = []
    for o in arr:
        cve = (o.get("cve") or o.get("id") or "").upper()
        if not CVE_RE.fullmatch(cve or ""):
            continue
        out.append(
            Finding(
                cve=cve,
                package=o.get("package", ""),
                version=o.get("version", ""),
                source="generic",
                asset=o.get("asset", "unknown"),
                cvss=float(o.get("cvss", 0) or 0),
                severity=o.get("severity", ""),
                title=o.get("title", ""),
            )
        )
    return out
