"""FIRST EPSS: probability of exploitation activity within 30 days.

FIRST explicitly warns EPSS has no environmental context and is not a
complete risk score, which is exactly why it is one input here, not the
whole decision.

Offline: bundled sample at data/epss-sample.csv.
Live: --refresh pulls the daily gzipped CSV from FIRST.
"""
from __future__ import annotations

import csv
import io
from typing import Dict, Optional, Tuple

from triage_core import data_dir

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


class EpssTable:
    def __init__(self, by_cve: Dict[str, Tuple[float, str]]):
        self._by_cve = by_cve

    def get(self, cve: str) -> Optional[Tuple[float, str]]:
        """Return (probability, date) if known, else None."""
        return self._by_cve.get(cve.upper())

    def __len__(self) -> int:
        return len(self._by_cve)

    @classmethod
    def load_sample(cls) -> "EpssTable":
        text = (data_dir() / "epss-sample.csv").read_text(encoding="utf-8")
        return cls(_parse(text))

    @classmethod
    def load_live(cls) -> "EpssTable":
        import gzip
        import urllib.request

        with urllib.request.urlopen(EPSS_URL, timeout=30) as r:  # noqa: S310
            raw = gzip.decompress(r.read()).decode("utf-8")
        return cls(_parse(raw))


def _parse(text: str) -> Dict[str, Tuple[float, str]]:
    out: Dict[str, Tuple[float, str]] = {}
    date = ""
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):
            # FIRST prepends "#model_version:...,score_date:YYYY-MM-DD..."
            for token in ",".join(row).split(","):
                if "score_date" in token:
                    date = token.split(":", 1)[-1].strip()
            continue
        if row[0].lower() == "cve":
            continue
        try:
            out[row[0].upper()] = (float(row[1]), date)
        except (IndexError, ValueError):
            continue
    return out
