"""CISA Known Exploited Vulnerabilities catalog.

Offline: bundled sample at data/kev-sample.json.
Live: --refresh pulls https://www.cisa.gov/.../known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import json
from typing import Dict, Optional

from triage_core import data_dir

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KevTable:
    def __init__(self, by_cve: Dict[str, str], mode: str):
        self._by_cve = by_cve
        self.mode = mode

    def get(self, cve: str) -> Optional[str]:
        """Return the dateAdded if the CVE is in KEV, else None."""
        return self._by_cve.get(cve.upper())

    def __len__(self) -> int:
        return len(self._by_cve)

    @classmethod
    def load_sample(cls) -> "KevTable":
        doc = json.loads((data_dir() / "kev-sample.json").read_text(encoding="utf-8"))
        return cls(_index(doc), "sample")

    @classmethod
    def load_live(cls) -> "KevTable":
        import urllib.request

        with urllib.request.urlopen(KEV_URL, timeout=30) as r:  # noqa: S310
            doc = json.loads(r.read().decode("utf-8"))
        return cls(_index(doc), "live")

    @classmethod
    def load_file(cls, path: str) -> "KevTable":
        from pathlib import Path
        return cls(_index(json.loads(Path(path).read_text(encoding="utf-8"))), "file")


def _index(doc: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for v in doc.get("vulnerabilities", []) or []:
        cve = (v.get("cveID") or "").upper()
        if cve:
            out[cve] = v.get("dateAdded", "")
    return out
