#!/usr/bin/env python3
"""Vulnerability remediation tracker.

Turns a vulnerability scanner export into a short list of who needs to fix
what, and by when:

1. De-duplicates findings by host and CVE, keeping the first time each was seen.
2. Matches every host to an owner.
3. Flags CVEs on CISA's Known Exploited Vulnerabilities (KEV) catalogue.
4. Sets a due date from the severity, with a shorter deadline for known-exploited CVEs.
5. Applies risk acceptances, but only when they name an approver and an expiry date,
   and never for known-exploited CVEs.
6. Writes a Markdown report and, optionally, one ticket per owner.

Usage:
    python vrt.py --scan data/scan_export.csv --owners data/asset_owners.csv \
        --kev data/kev_sample.csv --exceptions data/risk_acceptances.csv \
        --as-of 2026-09-28 --out data/sample_report.md --tickets-dir data/tickets
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

__version__ = "1.0.0"

# Example remediation policy, in calendar days from first detection.
SLA_DAYS = {"Critical": 14, "High": 30, "Medium": 60, "Low": 90}
KEV_SLA_DAYS = 7
IGNORED_SEVERITIES = {"Info", "Informational", "None"}
SEVERITY_ORDER = {s: i for i, s in enumerate(SLA_DAYS)}


class InputError(ValueError):
    """Raised when an input file cannot be used."""


def _read(path: str | Path, required: set[str]) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df.columns = [c.strip().lower() for c in df.columns]
    missing = required - set(df.columns)
    if missing:
        raise InputError(f"{Path(path).name}: missing column(s) " + ", ".join(sorted(missing)))
    return df


def load_scan(path: str | Path) -> tuple[pd.DataFrame, int]:
    """Return de-duplicated findings and the number of informational rows ignored."""
    df = _read(path, {"host", "cve", "severity", "first_seen"})
    df["host"] = df["host"].str.strip().str.upper()
    df["cve"] = df["cve"].str.strip().str.upper()
    df["severity"] = df["severity"].str.strip().str.title()
    ignored = df["severity"].isin(IGNORED_SEVERITIES)
    df = df[~ignored].copy()
    unknown = sorted(set(df["severity"]) - set(SLA_DAYS))
    if unknown:
        raise InputError("unknown severity value(s): " + ", ".join(unknown))
    df["first_seen"] = pd.to_datetime(df["first_seen"], errors="raise").dt.normalize()
    if "title" not in df.columns:
        df["title"] = ""
    df = (df.sort_values("first_seen")
            .drop_duplicates(["host", "cve"], keep="first")
            .reset_index(drop=True))
    return df, int(ignored.sum())


def load_kev(path: str | Path) -> set[str]:
    df = _read(path, {"cveid"})
    return set(df["cveid"].str.strip().str.upper())


def load_owners(path: str | Path) -> pd.DataFrame:
    df = _read(path, {"host", "owner"})
    df["host"] = df["host"].str.strip().str.upper()
    if "team" not in df.columns:
        df["team"] = ""
    return df[["host", "owner", "team"]].drop_duplicates("host")


def load_exceptions(path: str | Path | None) -> pd.DataFrame:
    columns = ["host", "cve", "approver", "expires", "reason"]
    if path is None:
        return pd.DataFrame(columns=columns)
    df = _read(path, {"host", "cve", "approver", "expires"})
    df["host"] = df["host"].str.strip().str.upper()
    df["cve"] = df["cve"].str.strip().str.upper()
    df["approver"] = df["approver"].str.strip()
    df["expires"] = pd.to_datetime(df["expires"].str.strip(), errors="coerce")
    if "reason" not in df.columns:
        df["reason"] = ""
    return df[columns]


def assess(findings: pd.DataFrame, kev: set[str], owners: pd.DataFrame,
           exceptions: pd.DataFrame, as_of: pd.Timestamp) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (findings with owner, due date and status; exceptions with a verdict)."""
    df = findings.merge(owners, on="host", how="left")
    df["owner"] = df["owner"].fillna("").replace("", "Unassigned")
    df["team"] = df["team"].fillna("")
    df["kev"] = df["cve"].isin(kev)
    base_days = df["severity"].map(SLA_DAYS)
    df["sla_days"] = base_days.where(~df["kev"], base_days.clip(upper=KEV_SLA_DAYS))
    df["due"] = df["first_seen"] + pd.to_timedelta(df["sla_days"], unit="D")
    df["days_open"] = (as_of - df["first_seen"]).dt.days
    df["days_overdue"] = (as_of - df["due"]).dt.days.clip(lower=0)

    # Judge each risk acceptance against the policy.
    ex = exceptions.copy()
    verdicts = []
    for _, row in ex.iterrows():
        if not row["approver"]:
            verdicts.append("Rejected: no named approver")
        elif pd.isna(row["expires"]):
            verdicts.append("Rejected: no valid expiry date")
        elif row["cve"] in kev:
            verdicts.append("Rejected: known exploited, must be fixed")
        elif row["expires"] < as_of:
            verdicts.append("Expired")
        else:
            verdicts.append("Active")
    ex["verdict"] = verdicts
    active = ex[ex["verdict"] == "Active"][["host", "cve", "approver", "expires"]]
    df = df.merge(active.rename(columns={"expires": "accepted_until"}), on=["host", "cve"], how="left")

    df["status"] = "Open"
    df.loc[df["due"] < as_of, "status"] = "Overdue"
    df.loc[df["accepted_until"].notna(), "status"] = "Risk accepted"
    df["sev_rank"] = df["severity"].map(SEVERITY_ORDER)
    df = df.sort_values(["kev", "sev_rank", "due"], ascending=[False, True, True]).reset_index(drop=True)
    return df, ex


def _md_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def _d(ts) -> str:
    return "" if pd.isna(ts) else pd.Timestamp(ts).strftime("%Y-%m-%d")


def render_report(df: pd.DataFrame, ex: pd.DataFrame, as_of: pd.Timestamp, ignored: int, kev_source: str) -> str:
    live = df[df["status"] != "Risk accepted"]
    lines = ["# Vulnerability remediation report", "",
             f"Report date: {as_of:%Y-%m-%d}  ",
             f"Findings after de-duplication: {len(df)} ({ignored} informational row(s) ignored)  ",
             f"Known-exploited list: `{kev_source}`", "",
             "## Summary", ""]
    rows = []
    for sev, days in SLA_DAYS.items():
        sub = live[live["severity"] == sev]
        rows.append([sev, f"{days} days", len(sub), int((sub["status"] == "Overdue").sum()), int(sub["kev"].sum())])
    lines += _md_table(["Severity", "Policy", "Outstanding", "Overdue", "Known exploited"], rows)
    lines += ["", f"Known-exploited CVEs get {KEV_SLA_DAYS} days whatever their severity.", ""]

    kev_rows = live[live["kev"]]
    lines += ["## Known-exploited findings", ""]
    if len(kev_rows):
        lines += _md_table(["Host", "CVE", "Severity", "Owner", "Due", "Status", "Days overdue"],
                           [[r.host, r.cve, r.severity, r.owner, _d(r.due), r.status, r.days_overdue]
                            for r in kev_rows.itertuples()])
    else:
        lines.append("None open.")

    overdue = live[live["status"] == "Overdue"]
    lines += ["", "## Overdue by owner", ""]
    if len(overdue):
        grouped = (overdue.groupby(["owner", "team"], dropna=False)
                          .agg(overdue=("cve", "size"), worst=("days_overdue", "max"))
                          .reset_index().sort_values(["overdue", "worst"], ascending=False))
        lines += _md_table(["Owner", "Team", "Overdue findings", "Most days overdue"],
                           [[r.owner, r.team, r.overdue, r.worst] for r in grouped.itertuples()])
    else:
        lines.append("Nothing overdue.")

    lines += ["", "## All findings", ""]
    lines += _md_table(["Host", "CVE", "Title", "Severity", "KEV", "First seen", "Due", "Status", "Owner"],
                       [[r.host, r.cve, r.title, r.severity, "yes" if r.kev else "", _d(r.first_seen), _d(r.due),
                         r.status, r.owner] for r in df.itertuples()])

    lines += ["", "## Risk acceptances", ""]
    if len(ex):
        lines += _md_table(["Host", "CVE", "Approver", "Expires", "Verdict", "Reason"],
                           [[r.host, r.cve, r.approver or "(none)", _d(r.expires) or "(none)", r.verdict, r.reason]
                            for r in ex.itertuples()])
        lines += ["", "Policy: an acceptance needs a named approver and an expiry date, "
                      "and known-exploited CVEs cannot be accepted."]
    else:
        lines.append("None recorded.")
    lines += ["", f"_Generated by vrt {__version__}._", ""]
    return "\n".join(lines)


def write_owner_tickets(df: pd.DataFrame, as_of: pd.Timestamp, folder: str | Path) -> list[Path]:
    """One Markdown ticket per owner listing the findings they need to fix."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    live = df[df["status"] != "Risk accepted"]
    for owner, sub in live.groupby("owner"):
        slug = re.sub(r"[^a-z0-9]+", "-", owner.lower()).strip("-") or "unassigned"
        n_overdue = int((sub["status"] == "Overdue").sum())
        lines = [f"# Remediation request: {owner}", "",
                 f"Raised {as_of:%Y-%m-%d}. You own {len(sub)} open finding(s), {n_overdue} overdue.", ""]
        lines += _md_table(["Host", "CVE", "Title", "Severity", "Due", "Status"],
                           [[r.host, r.cve, r.title, r.severity + (" (known exploited)" if r.kev else ""),
                             _d(r.due), r.status] for r in sub.itertuples()])
        lines += ["", "Fix known-exploited items first. If a fix is not possible before the due date, "
                      "raise a risk acceptance with a named approver and an expiry date.", ""]
        path = folder / f"{slug}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Who needs to fix what, and by when, from a scanner export.")
    parser.add_argument("--scan", required=True, help="scanner export CSV (host, cve, severity, first_seen[, title])")
    parser.add_argument("--owners", required=True, help="asset owners CSV (host, owner[, team])")
    parser.add_argument("--kev", required=True, help="CISA KEV catalogue CSV (cveID column)")
    parser.add_argument("--exceptions", help="risk acceptances CSV (host, cve, approver, expires[, reason])")
    parser.add_argument("--as-of", help="report date YYYY-MM-DD (default: today)")
    parser.add_argument("--out", help="write the Markdown report here (default: print it)")
    parser.add_argument("--tickets-dir", help="also write one ticket per owner into this folder")
    args = parser.parse_args(argv)
    try:
        as_of = pd.Timestamp(args.as_of).normalize() if args.as_of else pd.Timestamp.today().normalize()
        findings, ignored = load_scan(args.scan)
        df, ex = assess(findings, load_kev(args.kev), load_owners(args.owners),
                        load_exceptions(args.exceptions), as_of)
    except (InputError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = render_report(df, ex, as_of, ignored, Path(args.kev).name)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Report written to {args.out}")
    else:
        print(report)
    if args.tickets_dir:
        paths = write_owner_tickets(df, as_of, args.tickets_dir)
        print(f"{len(paths)} owner ticket(s) written to {args.tickets_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
