import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vrt  # noqa: E402

AS_OF = pd.Timestamp("2026-09-28")


def csv(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def files(tmp_path):
    scan = csv(tmp_path, "scan.csv",
               "host,cve,severity,title,first_seen\n"
               "app01,CVE-2021-44228,Critical,Log4Shell,2026-09-10\n"
               "APP01,CVE-2021-44228,Critical,Log4Shell,2026-09-17\n"     # repeat from a later scan
               "web01,CVE-2023-48795,Medium,Terrapin,2026-06-29\n"
               "fs01,CVE-2016-2183,medium,SWEET32,2026-09-01\n"
               "laptop-01,CVE-2022-0778,High,OpenSSL loop,2026-09-20\n"
               "fs01,NONE,Info,Certificate details,2026-09-01\n")
    owners = csv(tmp_path, "owners.csv", "host,owner,team\nAPP01,App team,Apps\nWEB01,Web team,Apps\nFS01,Server team,IT Ops\n")
    kev = csv(tmp_path, "kev.csv", "cveID,vendorProject\nCVE-2021-44228,Apache\n")
    return scan, owners, kev


def run(files, exceptions_text=None, tmp_path=None):
    scan, owners, kev = files
    findings, ignored = vrt.load_scan(scan)
    ex = vrt.load_exceptions(csv(tmp_path, "ex.csv", exceptions_text) if exceptions_text else None)
    df, ex = vrt.assess(findings, vrt.load_kev(kev), vrt.load_owners(owners), ex, AS_OF)
    return df.set_index(["host", "cve"]), ex, ignored


def test_deduplicates_and_keeps_first_sighting(files):
    findings, ignored = vrt.load_scan(files[0])
    log4 = findings[findings["cve"] == "CVE-2021-44228"]
    assert len(log4) == 1
    assert log4.iloc[0]["first_seen"] == pd.Timestamp("2026-09-10")
    assert ignored == 1                                   # the Info row


def test_known_exploited_gets_seven_days_whatever_the_severity(files, tmp_path):
    df, _, _ = run(files, tmp_path=tmp_path)
    row = df.loc[("APP01", "CVE-2021-44228")]
    assert bool(row["kev"]) is True
    assert row["sla_days"] == 7
    assert row["due"] == pd.Timestamp("2026-09-17")
    assert row["status"] == "Overdue" and row["days_overdue"] == 11


def test_due_dates_follow_severity_policy(files, tmp_path):
    df, _, _ = run(files, tmp_path=tmp_path)
    terrapin = df.loc[("WEB01", "CVE-2023-48795")]
    assert terrapin["sla_days"] == 60 and terrapin["status"] == "Overdue"      # due 2026-08-28
    sweet32 = df.loc[("FS01", "CVE-2016-2183")]
    assert sweet32["severity"] == "Medium" and sweet32["status"] == "Open"    # due 2026-10-31


def test_unknown_host_is_unassigned(files, tmp_path):
    df, _, _ = run(files, tmp_path=tmp_path)
    assert df.loc[("LAPTOP-01", "CVE-2022-0778")]["owner"] == "Unassigned"


def test_risk_acceptance_rules(files, tmp_path):
    text = ("host,cve,approver,expires,reason\n"
            "FS01,CVE-2016-2183,Head of IT,2026-12-31,Legacy appliance\n"      # valid
            "WEB01,CVE-2023-48795,,2026-12-31,No approver\n"                    # rejected
            "APP01,CVE-2021-44228,Head of IT,2026-12-31,Vendor delay\n"         # known exploited
            "LAPTOP-01,CVE-2022-0778,Head of IT,2026-09-01,Old acceptance\n")   # expired
    df, ex, _ = run(files, text, tmp_path)
    verdicts = dict(zip(ex["cve"], ex["verdict"]))
    assert verdicts["CVE-2016-2183"] == "Active"
    assert verdicts["CVE-2023-48795"].startswith("Rejected: no named approver")
    assert verdicts["CVE-2021-44228"].startswith("Rejected: known exploited")
    assert verdicts["CVE-2022-0778"] == "Expired"
    assert df.loc[("FS01", "CVE-2016-2183")]["status"] == "Risk accepted"
    assert df.loc[("APP01", "CVE-2021-44228")]["status"] == "Overdue"          # acceptance ignored
    assert df.loc[("WEB01", "CVE-2023-48795")]["status"] == "Overdue"


def test_unknown_severity_is_an_error(tmp_path):
    scan = csv(tmp_path, "scan.csv", "host,cve,severity,first_seen\nA,CVE-1,Urgent,2026-09-01\n")
    with pytest.raises(vrt.InputError):
        vrt.load_scan(scan)


def test_cli_writes_report_and_owner_tickets(files, tmp_path):
    scan, owners, kev = files
    out = tmp_path / "report.md"
    tickets = tmp_path / "tickets"
    code = vrt.main(["--scan", str(scan), "--owners", str(owners), "--kev", str(kev),
                     "--as-of", "2026-09-28", "--out", str(out), "--tickets-dir", str(tickets)])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "## Known-exploited findings" in text and "CVE-2021-44228" in text
    names = sorted(p.name for p in tickets.iterdir())
    assert names == ["app-team.md", "server-team.md", "unassigned.md", "web-team.md"]
