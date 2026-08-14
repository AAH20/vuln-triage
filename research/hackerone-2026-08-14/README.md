# HackerOne opportunity filter — 2026-08-14

This corpus records a read-only, authenticated HackerOne opportunity filter for bounty programs with domain assets tagged as Nginx. It is research input, not evidence that any company is vulnerable.

Deribit ranked first because its current program rules explicitly define vulnerable-component waiting periods and require initial testing on `test.deribit.com`. Production and wildcard assets are deliberately marked `active_testing: false` because the program states that live-environment testing requires additional authorization through a valid open ticket.

The HackerOne technology tag provides product-level evidence only. It does not establish the installed version or vulnerable module. The expected correlation level is therefore L1 (`insufficient_evidence`).

Run:

```bash
PYTHONPATH=packages python -m triage_correlate.cli \
  --scope research/hackerone-2026-08-14/deribit-scope.json \
  --observations research/hackerone-2026-08-14/deribit-observations.json \
  --advisories research/hackerone-2026-08-14/nginx-advisories.json \
  --out research/hackerone-2026-08-14/deribit-correlation.json
```

No active network requests are made by `triage-correlate`.
