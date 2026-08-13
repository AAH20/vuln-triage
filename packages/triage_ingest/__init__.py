"""triage_ingest: scanner-agnostic adapters.

We do not scan. We consume the output of whatever scanner the customer
already runs (Trivy, Grype, OpenVAS, Nmap NSE, or a plain CVE list) and
normalize it to a list[Finding]. Owning the layer above the scanners is
the whole point: never ask anyone to switch tools.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from triage_core import Finding

from . import generic, grype, trivy


def detect_and_load(path: str) -> List[Finding]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    # Plain CVE list (csv/txt) has no JSON envelope.
    stripped = text.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return generic.load(text)
    doc = json.loads(text)
    if isinstance(doc, dict) and "Results" in doc:
        return trivy.load(doc)
    if isinstance(doc, dict) and "matches" in doc:
        return grype.load(doc)
    # A bare JSON array of {cve, package, ...} objects.
    return generic.load_json(doc)


__all__ = ["detect_and_load", "trivy", "grype", "generic"]
