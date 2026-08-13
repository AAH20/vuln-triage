"""`triage` — ingest any scanner's output, enrich with real-world exploitation
intelligence, decide, and report.

    triage --input scan.json
    triage --input scan.json --assets assets.json --format memo
    triage --input scan.json --refresh   # pull live CISA KEV + FIRST EPSS
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

from triage_core import Asset
from triage_decide import decide_all
from triage_enrich import EpssTable, KevTable, enrich
from triage_ingest import detect_and_load
from triage_report import board_memo, terminal_summary, treatment_register


def _load_assets(path: str) -> tuple[Dict[str, Asset], Asset]:
    default = Asset(name="default", internet_facing=False, criticality="medium")
    if not path:
        return {}, default
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    assets: Dict[str, Asset] = {}
    for name, cfg in doc.items():
        if name == "default":
            default = Asset(
                name="default",
                internet_facing=bool(cfg.get("internet_facing", False)),
                criticality=cfg.get("criticality", "medium"),
                loss_scenario_low_usd=cfg.get("loss_scenario_low_usd"),
                loss_scenario_high_usd=cfg.get("loss_scenario_high_usd"),
                loss_scenario_source=cfg.get("loss_scenario_source", ""),
            )
            continue
        assets[name] = Asset(
            name=name,
            internet_facing=bool(cfg.get("internet_facing", False)),
            criticality=cfg.get("criticality", "medium"),
            loss_scenario_low_usd=cfg.get("loss_scenario_low_usd"),
            loss_scenario_high_usd=cfg.get("loss_scenario_high_usd"),
            loss_scenario_source=cfg.get("loss_scenario_source", ""),
        )
    return assets, default


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="triage",
        description="Exploit-aware vulnerability triage. Stop scanning, start deciding.",
    )
    p.add_argument("--input", "-i", required=True, help="scanner output (Trivy/Grype JSON, or CVE list)")
    p.add_argument("--assets", "-a", default="", help="asset context JSON (reachability, criticality, value)")
    p.add_argument("--format", "-f", default="table", choices=["table", "register", "memo"])
    p.add_argument("--out", "-o", default="", help="write output to a file instead of stdout")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--refresh", action="store_true", help="pull live CISA KEV and FIRST EPSS feeds")
    source.add_argument("--demo", action="store_true", help="use bundled samples; every decision is UNKNOWN")
    source.add_argument("--feed-files", nargs=2, metavar=("KEV_JSON", "EPSS_CSV"), help="use supplied feed snapshots")
    args = p.parse_args(argv)

    findings = detect_and_load(args.input)
    if not findings:
        print("No findings parsed from input.", file=sys.stderr)
        return 1

    if args.refresh:
        kev = KevTable.load_live()
        epss = EpssTable.load_live()
    elif args.demo:
        kev = KevTable.load_sample()
        epss = EpssTable.load_sample()
    else:
        kev = KevTable.load_file(args.feed_files[0])
        epss = EpssTable.load_file(args.feed_files[1])

    enriched = enrich(findings, kev, epss)
    assets, default = _load_assets(args.assets)
    verdicts = decide_all(enriched, assets, default)

    if args.format == "register":
        output = treatment_register(verdicts)
    elif args.format == "memo":
        output = board_memo(verdicts)
    else:
        output = terminal_summary(verdicts)

    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.format} to {args.out}", file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
