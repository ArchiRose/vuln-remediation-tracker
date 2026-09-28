# Vulnerability remediation tracker

![tests](https://github.com/ArchiRose/vuln-remediation-tracker/actions/workflows/tests.yml/badge.svg)

Turns a weekly vulnerability scanner export into a short list of **who needs to fix what, and by when**.

1. **De-duplicates** findings by host and CVE, keeping the date each was first seen. Scanners repeat the same finding every week.
2. **Matches every host to an owner**. Hosts nobody owns show up as `Unassigned`, which is a finding in itself.
3. **Checks CISA's Known Exploited Vulnerabilities (KEV) catalogue**. Known-exploited CVEs get 7 days whatever their severity score.
4. **Sets a due date from the severity**, using an example policy: Critical 14 days, High 30, Medium 60, Low 90.
5. **Applies risk acceptances only when they are valid**. Each one needs a named approver and an expiry date. Known-exploited CVEs can never be accepted, and expired acceptances stop counting.
6. **Writes a Markdown report** (summary, known-exploited list, overdue by owner, every finding, every acceptance and its verdict). Optionally it also writes **one remediation ticket per owner**.

Part of my portfolio: [archirose.github.io](https://archirose.github.io) (design SOC-05).

## Quick start

```bash
pip install -r requirements.txt
python vrt.py --scan data/scan_export.csv --owners data/asset_owners.csv \
    --kev data/kev_sample.csv --exceptions data/risk_acceptances.csv \
    --as-of 2026-09-28 --out report.md --tickets-dir tickets
```

The output is in [`data/sample_report.md`](data/sample_report.md), and the per-owner tickets are in [`data/tickets/`](data/tickets/).

The sample hosts, IP addresses, owners and acceptances are made up. The CVEs are real, well-known ones, so the example reads naturally. [`data/kev_sample.csv`](data/kev_sample.csv) is a **five-row excerpt** of the KEV catalogue, and in this demo a CVE counts as known-exploited only if it appears in that excerpt. For real use, download the full catalogue in CSV format from [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Input files

| File | Required columns | Optional |
|---|---|---|
| Scanner export (`--scan`) | `host`, `cve`, `severity` (Critical/High/Medium/Low), `first_seen` | `title`. `Info` rows are ignored |
| Asset owners (`--owners`) | `host`, `owner` | `team` |
| KEV catalogue (`--kev`) | `cveID` | Uses the same column name as CISA's file |
| Risk acceptances (`--exceptions`) | `host`, `cve`, `approver`, `expires` | `reason` |

Most scanners (Nessus, OpenVAS, Defender Vulnerability Management) can export this shape with a little column renaming.

## Why these rules

- **Known-exploited first.** An attacker is already using a KEV-listed CVE somewhere, so it is fixed ahead of a higher-scored CVE that nobody is exploiting.
- **Every acceptance expires.** An acceptance without an owner and an end date turns into a permanent hole. The report shows rejected and expired acceptances next to valid ones, so they get cleaned up.
- **Owners get their own list.** One ticket per owner, with the known-exploited items marked, gets more fixed than one long spreadsheet.

The policy numbers are examples. Change `SLA_DAYS` and `KEV_SLA_DAYS` at the top of `vrt.py` to match your organisation's policy.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

The tests cover de-duplication, the known-exploited deadline, the due dates for each severity, unassigned hosts, every risk-acceptance verdict and the command line. GitHub Actions runs them on Python 3.11 and 3.12 for every push.

## Licence

MIT
