"""triage_core: shared models, paths and impact defaults."""
from .models import IMPACT_BY_CRITICALITY, Asset, Enriched, Finding, Verdict
from .paths import data_dir, repo_root

__all__ = [
    "Asset",
    "Enriched",
    "Finding",
    "Verdict",
    "IMPACT_BY_CRITICALITY",
    "data_dir",
    "repo_root",
]
