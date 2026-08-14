"""Contract tests for authorization, applicability and benchmark behavior."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from triage_correlate import Advisory, Observation, ScopeReceipt, ScopeTarget, correlate, naive_correlate, scope_digest  # noqa: E402


TARGETS = [
    ScopeTarget("*.example.test", True, True),
    ScopeTarget("admin.example.test", False, False),
]
SCOPE = ScopeReceipt("test", "2026-08-14T00:00:00Z", scope_digest(TARGETS), TARGETS)
ADV = Advisory(
    "CVE-2099-0001",
    "EdgeServer",
    "Acme",
    "2.0.0",
    "3.0.0",
    required_component="proxy",
    kev=True,
    epss=0.9,
)


def test_explicit_scope_exclusion_wins():
    rows = correlate(SCOPE, [Observation("admin.example.test", "EdgeServer", "Acme", "2.5.0", 1.0)], [ADV])
    assert rows == []


def test_tampered_scope_receipt_is_rejected():
    receipt = ScopeReceipt("test", "now", "sha256:tampered", TARGETS)
    try:
        correlate(receipt, [], [])
    except ValueError as error:
        assert "hash mismatch" in str(error)
    else:
        raise AssertionError("tampered receipt was accepted")


def test_out_of_scope_assets_are_not_correlated():
    rows = correlate(SCOPE, [Observation("outside.test", "EdgeServer", "Acme", "2.5.0", 1.0)], [ADV])
    assert rows == []


def test_affected_version_is_candidate_and_permitted():
    row = correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "2.5.0", 1.0, "now", components=["proxy"])], [ADV])[0]
    assert row.status == "validation_candidate"
    assert row.evidence_level == "L3"
    assert row.active_validation_permitted is True


def test_fixed_version_is_rejected():
    rows = correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "3.0.0", 1.0)], [ADV])
    assert rows == []


def test_unknown_version_is_not_reportable():
    row = correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "", 0.8)], [ADV])[0]
    assert row.status == "insufficient_evidence"
    assert row.evidence_level == "L1"
    assert row.active_validation_permitted is False


def test_required_component_must_be_proven():
    row = correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "2.5.0", 1.0, "now")], [ADV])[0]
    assert row.status == "insufficient_evidence"
    assert "not proven" in row.contradictions[0]


def test_naive_baseline_keeps_fixed_and_out_of_scope_noise():
    observations = [
        Observation("api.example.test", "EdgeServer", "Acme", "3.0.0", 1.0),
        Observation("outside.test", "EdgeServer", "Acme", "2.5.0", 1.0),
    ]
    assert len(naive_correlate(observations, [ADV])) == 2
    assert correlate(SCOPE, observations, [ADV]) == []


def test_discontinuous_ranges_do_not_fill_safe_gap():
    advisory = Advisory(
        "CVE-2099-0002",
        "EdgeServer",
        "Acme",
        affected_ranges=[
            {"introduced": "1.0", "fixed": "1.5"},
            {"introduced": "2.0", "fixed": "2.5"},
        ],
    )
    assert correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "1.7", 1.0)], [advisory]) == []
    assert correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "2.2", 1.0)], [advisory])[0].evidence_level == "L2"


def test_boolean_applicability_requires_every_fact():
    advisory = Advisory(
        "CVE-2099-0003",
        "EdgeServer",
        "Acme",
        "2.0",
        "3.0",
        applicability={"all": [{"component": "http3"}, {"protocol": "h3"}, {"reachable": True}]},
    )
    partial = Observation("api.example.test", "EdgeServer", "Acme", "2.5", 1.0, "now", components=["http3"])
    row = correlate(SCOPE, [partial], [advisory])[0]
    assert row.status == "insufficient_evidence"
    complete = Observation(
        "api.example.test",
        "EdgeServer",
        "Acme",
        "2.5",
        1.0,
        "now",
        components=["http3"],
        protocols=["h3"],
        reachable=True,
        source_type="credentialed_inventory",
    )
    row = correlate(SCOPE, [complete], [advisory])[0]
    assert row.evidence_level == "L3"
    assert row.status == "validation_candidate"


def test_exploit_signal_does_not_promote_unknown_asset_applicability():
    advisory = Advisory(
        "CVE-2099-0004",
        "EdgeServer",
        "Acme",
        "2.0",
        "3.0",
        required_component="proxy",
        kev=True,
        exploit_sources=[{"source": "exploit-db", "verified": True, "confidence": 1.0}],
    )
    row = correlate(SCOPE, [Observation("api.example.test", "EdgeServer", "Acme", "", 1.0)], [advisory])[0]
    assert row.exploit_confidence == 1.0
    assert row.status == "insufficient_evidence"
    assert row.active_validation_permitted is False


def test_expired_evidence_cannot_be_promoted():
    observation = Observation(
        "api.example.test",
        "EdgeServer",
        "Acme",
        "2.5",
        1.0,
        "2026-01-01T00:00:00Z",
        components=["proxy"],
        expires_at="2026-02-01T00:00:00Z",
        source_type="sbom",
    )
    row = correlate(SCOPE, [observation], [ADV], as_of="2026-08-14T00:00:00Z")[0]
    assert row.evidence_expired is True
    assert row.status == "insufficient_evidence"
    assert row.vulnerable_probability == 0.0


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} correlation contract tests passed")
