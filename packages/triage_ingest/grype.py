"""Adapter for Grype JSON output (`grype -o json`)."""
from __future__ import annotations

from typing import List

from triage_core import Finding


def _cvss(vuln: dict) -> float:
    best = 0.0
    for c in vuln.get("cvss", []) or []:
        try:
            best = max(best, float(c.get("metrics", {}).get("baseScore", 0)))
        except (TypeError, ValueError):
            pass
    return best


def load(doc: dict) -> List[Finding]:
    findings: List[Finding] = []
    asset = (doc.get("source", {}) or {}).get("target", {})
    asset_name = asset.get("userInput") if isinstance(asset, dict) else "unknown"
    for m in doc.get("matches", []) or []:
        vuln = m.get("vulnerability", {}) or {}
        cve = vuln.get("id", "")
        if not cve:
            continue
        artifact = m.get("artifact", {}) or {}
        findings.append(
            Finding(
                cve=cve,
                package=artifact.get("name", ""),
                version=artifact.get("version", ""),
                source="grype",
                asset=asset_name or "unknown",
                cvss=_cvss(vuln),
                severity=vuln.get("severity", ""),
                title=vuln.get("description", "")[:120],
            )
        )
    return findings
