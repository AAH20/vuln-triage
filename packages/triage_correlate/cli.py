"""CLI for passive scope-to-CVE correlation and baseline comparison."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .engine import correlate, naive_correlate
from .models import Advisory, Observation, ScopeReceipt, ScopeTarget


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="triage-correlate",
        description="Passive authorized asset-to-CVE correlation; never scans targets.",
    )
    parser.add_argument("--scope", required=True, help="scope receipt JSON")
    parser.add_argument("--observations", required=True, help="passive technology observations JSON")
    parser.add_argument("--advisories", required=True, help="normalized vendor advisories JSON")
    parser.add_argument("--ground-truth", default="", help="optional labeled asset/CVE pairs for precision and recall")
    parser.add_argument("--as-of", default="", help="ISO-8601 evaluation time for deterministic evidence expiry")
    parser.add_argument("--out", default="", help="optional JSON output path")
    args = parser.parse_args(argv)

    scope_doc = _load(args.scope)
    receipt = ScopeReceipt(
        program=scope_doc["program"],
        retrieved_at=scope_doc["retrieved_at"],
        rules_hash=scope_doc["rules_hash"],
        targets=[ScopeTarget(**row) for row in scope_doc["targets"]],
    )
    observations = [Observation(**row) for row in _load(args.observations)]
    advisories = [Advisory(**row) for row in _load(args.advisories)]
    baseline = naive_correlate(observations, advisories)
    results = correlate(receipt, observations, advisories, as_of=args.as_of, include_rejected=True)
    candidates = [row for row in results if row.status == "validation_candidate"]
    reduction = 0.0 if not baseline else 1 - (len(candidates) / len(baseline))
    candidate_pairs = {(row.asset, row.cve) for row in candidates}
    rejected = [row for row in results if row.status == "rejected"]
    insufficient = [row for row in results if row.status == "insufficient_evidence"]
    weighted_signal = sum({"L1": 1, "L2": 2, "L3": 3, "L4": 4}.get(row.evidence_level, 0) for row in results if row.status != "rejected")
    noise = len(rejected) + len(insufficient)
    quality = {}
    if args.ground_truth:
        truth = {(row["asset"], row["cve"]) for row in _load(args.ground_truth)}
        baseline_set = set(baseline)

        def metrics(predicted):
            true_positive = len(predicted & truth)
            return {
                "true_positive": true_positive,
                "false_positive": len(predicted - truth),
                "false_negative": len(truth - predicted),
                "precision": round(true_positive / len(predicted), 4) if predicted else 0.0,
                "recall": round(true_positive / len(truth), 4) if truth else 0.0,
            }

        quality = {"baseline": metrics(baseline_set), "policy": metrics(candidate_pairs)}
    payload = {
        "mode": "passive_correlation_only",
        "program": receipt.program,
        "scope_receipt": {"retrieved_at": receipt.retrieved_at, "rules_hash": receipt.rules_hash},
        "benchmark": {
            "naive_candidates": len(baseline),
            "version_constrained_candidates": len(candidates),
            "candidate_reduction": round(reduction, 4),
            "out_of_scope_active_requests": 0,
            "network_requests": 0,
            "quality": quality,
            "rejected_by_policy": len(rejected),
            "insufficient_evidence": len(insufficient),
            "evidence_weighted_snr": round(weighted_signal / noise, 4) if noise else float(weighted_signal),
            "entity_populations": {
                "potentially_associated": len({row.asset for row in results}),
                "version_applicable": len({row.asset for row in results if row.evidence_level in ("L2", "L3") and row.status != "rejected"}),
                "configuration_applicable": len({row.asset for row in results if row.evidence_level == "L3" and row.status == "validation_candidate"}),
                "verified_vulnerable": 0
            },
        },
        "correlations": [asdict(row) for row in results],
    }
    output = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(f"wrote correlation benchmark to {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
