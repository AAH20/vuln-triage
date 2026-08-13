"""Property tests for the decision engine.

These assert invariants the engine must always hold, independent of any
specific implementation. An agent (or a future refactor) has to satisfy
constraints it did not author. Run: PYTHONPATH=packages python -m pytest -q
(or plain `python tests/test_decide.py`).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from triage_core import Asset, Enriched, Finding  # noqa: E402
from triage_decide import decide  # noqa: E402


def _f(cve="CVE-2021-44228", cvss=10.0):
    return Finding(cve=cve, package="p", version="1", source="test", asset="a", cvss=cvss)


CRIT = Asset(name="a", internet_facing=True, criticality="critical")
INTERNAL = Asset(name="a", internet_facing=False, criticality="medium")


def test_kev_reachable_critical_is_fix_now():
    v = decide(Enriched(finding=_f(), kev=True, epss=0.9), CRIT)
    assert v.tier == "fix_now"
    assert v.deadline_days == 7
    assert v.attack_path  # a narrative chain is attached


def test_non_kev_low_epss_is_monitor_even_at_cvss_98():
    # The whole thesis: CVSS 9.8 alone does not mean act.
    v = decide(Enriched(finding=_f(cve="CVE-2023-45853", cvss=9.8), kev=False, epss=0.004), CRIT)
    assert v.tier == "monitor"
    assert v.deadline_days == 0


def test_non_kev_high_epss_is_fix_cycle():
    v = decide(Enriched(finding=_f(cve="CVE-2023-38545", cvss=9.8), kev=False, epss=0.11), CRIT)
    assert v.tier == "fix_cycle"
    assert v.deadline_days == 30


def test_kev_but_internal_is_not_fix_now():
    v = decide(Enriched(finding=_f(cve="CVE-2022-1388"), kev=True, epss=0.9), INTERNAL)
    assert v.tier == "fix_cycle"


def test_kev_beats_higher_cvss_noise_in_ordering():
    kev_low_cvss = decide(Enriched(finding=_f(cve="CVE-1", cvss=6.0), kev=True, epss=0.9), CRIT)
    noise_high_cvss = decide(Enriched(finding=_f(cve="CVE-2", cvss=9.8), kev=False, epss=0.004), CRIT)
    assert kev_low_cvss.score > noise_high_cvss.score


def test_deterministic():
    e = Enriched(finding=_f(), kev=True, epss=0.9)
    a = decide(e, CRIT)
    b = decide(e, CRIT)
    assert (a.tier, a.score, a.expected_loss_low, a.expected_loss_high) == (
        b.tier, b.score, b.expected_loss_low, b.expected_loss_high
    )


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
