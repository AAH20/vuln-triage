"""Adapter for Trivy JSON output (`trivy image -f json`)."""
from __future__ import annotations

from typing import List

from triage_core import Finding


def _cvss(v: dict) -> float:
    cvss = v.get("CVSS") or {}
    for vendor in cvss.values():
        for key in ("V3Score", "V4Score", "V2Score"):
            if isinstance(vendor, dict) and vendor.get(key):
                try:
                    return float(vendor[key])
                except (TypeError, ValueError):
                    pass
    return 0.0


def load(doc: dict) -> List[Finding]:
    findings: List[Finding] = []
    for result in doc.get("Results", []) or []:
        asset = doc.get("ArtifactName") or result.get("Target") or "unknown"
        for v in result.get("Vulnerabilities", []) or []:
            cve = v.get("VulnerabilityID", "")
            if not cve:
                continue
            findings.append(
                Finding(
                    cve=cve,
                    package=v.get("PkgName", ""),
                    version=v.get("InstalledVersion", ""),
                    source="trivy",
                    asset=asset,
                    cvss=_cvss(v),
                    severity=v.get("Severity", ""),
                    title=v.get("Title", "") or v.get("Description", "")[:120],
                )
            )
    return findings
