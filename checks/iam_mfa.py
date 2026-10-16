#!/usr/bin/env python3
"""
iam_mfa.py - Evidence collector: MFA enforcement on AWS root and IAM users.

Control mapping:
  US  (SOC 2)       : CC6.1 - Logical access security / authentication
  EU  (ISO 27001)   : A.5.17 Authentication information, A.8.5 Secure authentication
  GCC (SAMA CSF)    : 3.3.5 Identity & Access Management (MFA for privileged/remote access)
  GCC (NCA ECC)     : 2-2 Identity and Access Management

Data source (in order):
  1. IAM credential report  - the standard auditor artifact (covers root + all users)
  2. Per-user API calls     - fallback if the report is blocked
  An organization SCP can deny some IAM reads. Anything we cannot verify is
  reported as UNKNOWN with the reason, never silently passed.

Usage:
  python checks/iam_mfa.py --profile grc-auditor --out evidence/iam_mfa.json

Exit code: 0 = PASS, 1 = FAIL (at least one FAIL), 2 = could not verify
(at least one UNKNOWN, no FAIL) (CI-friendly).
"""
import argparse
import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def _err(e):
    return e.response.get("Error", {}).get("Code", "Unknown")


def mask_account_id(account_id):
    """Redact all but the last 4 digits, e.g. 374786578995 -> ********8995."""
    return "*" * (len(account_id) - 4) + account_id[-4:]


def root_mfa_live(iam):
    """Live (uncached) root MFA status via account summary.

    The credential report is cached for up to 4 hours, but get_account_summary
    is not cached. Root MFA is checked via this live call every run, instead
    of trusting the report's mfa_active value for root, so enabling root MFA
    is reflected immediately rather than up to 4 hours later.
    """
    try:
        return iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled", 0) == 1
    except ClientError:
        return None


def get_credential_report(iam):
    """Return (rows, generated_at) from the IAM credential report, or raise ClientError.

    AWS caches this report for up to 4 hours, so generated_at can predate a
    change (e.g. root MFA enabled minutes ago) made after the cached report
    was built. Evidence consumers should check this timestamp before trusting
    a PASS as current.
    """
    for _ in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(2)
    resp = iam.get_credential_report()
    content = resp["Content"].decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))
    generated_at = resp["GeneratedTime"].astimezone(timezone.utc).isoformat()
    return rows, generated_at


def evaluate(name, console, mfa, source):
    if console is None or mfa is None:
        status = "UNKNOWN"
    elif not console:
        status = "N/A"            # no console password -> MFA control doesn't apply
    else:
        status = "PASS" if mfa else "FAIL"
    return {"resource": name, "console_access": console, "mfa_enabled": mfa,
            "status": status, "source": source}


def from_report(rows):
    # Root is handled separately in main() via a live call (root_mfa_live),
    # not from this (up to 4h stale) report, so its row is skipped here.
    out = []
    for r in rows:
        if r["user"] == "<root_account>":
            continue
        out.append(evaluate(r["user"], r["password_enabled"] == "true",
                            r["mfa_active"] == "true", "credential_report"))
    return out


def from_api(iam):
    # Root is handled separately in main() via a live call (root_mfa_live).
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            note = None
            try:
                iam.get_login_profile(UserName=name)
                console = True
            except ClientError as e:
                if _err(e) == "NoSuchEntity":
                    console = False
                else:
                    console, note = None, f"get_login_profile: {_err(e)}"
            try:
                mfa = len(iam.list_mfa_devices(UserName=name)["MFADevices"]) > 0
            except ClientError as e:
                mfa, note = None, f"list_mfa_devices: {_err(e)}"
            f = evaluate(name, console, mfa, "iam_api")
            if note:
                f["note"] = note
            out.append(f)
    return out


def main():
    p = argparse.ArgumentParser(description="Check MFA on AWS root and IAM users.")
    p.add_argument("--profile", default=None, help="AWS CLI profile name")
    default_out = f"evidence/iam_mfa_{datetime.now(timezone.utc):%Y-%m-%d_%H%M}.json"
    p.add_argument("--out", default=default_out,
                    help=f"Write JSON evidence to this file (default: dated path under "
                         f"evidence/, e.g. {default_out}, so each run keeps its own history)")
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile)
    iam = session.client("iam")
    account_id = session.client("sts").get_caller_identity()["Account"]

    root_finding = evaluate("root", True, root_mfa_live(iam), "account_summary_live")

    report_generated_at = None
    try:
        rows, report_generated_at = get_credential_report(iam)
        findings = [root_finding] + from_report(rows)
    except ClientError as e:
        print(f"Credential report unavailable ({_err(e)}); falling back to IAM API calls.")
        findings = [root_finding] + from_api(iam)

    failed = [f for f in findings if f["status"] == "FAIL"]
    unknown = [f for f in findings if f["status"] == "UNKNOWN"]
    not_applicable = [f for f in findings if f["status"] == "N/A"]
    result = "FAIL" if failed else ("PARTIAL" if unknown else "PASS")

    evidence = {
        "check_id": "IAM-MFA-001",
        "title": "MFA enabled for root and all console IAM users",
        "account_id": mask_account_id(account_id),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "credential_report_generated_at": report_generated_at,
        "controls": {"SOC2": ["CC6.1"], "ISO27001_2022": ["A.5.17", "A.8.5"],
                     "SAMA_CSF": ["3.3.5"], "NCA_ECC": ["2-2"]},
        "result": result,
        "summary": {"total": len(findings), "failed": len(failed), "unknown": len(unknown),
                    "not_applicable": len(not_applicable)},
        "findings": findings,
    }

    if report_generated_at:
        print(f"Credential report generated at: {report_generated_at} "
              f"(AWS caches this for up to 4 hours; IAM user findings may lag recent changes. "
              f"Root is checked live, not from this report.)")
    for f in findings:
        line = (f"[{f['status']:<7}] {f['resource']:<20} console={f['console_access']!s:<5} "
                f"mfa={f['mfa_enabled']!s:<5} via {f['source']}")
        print(line + (f"  ({f['note']})" if "note" in f else ""))
    print(f"\nRESULT: {result}  (failed={len(failed)}, unknown={len(unknown)}, "
          f"not_applicable={len(not_applicable)}, total={len(findings)})")

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(evidence, fh, indent=2)
        print(f"Evidence written to {args.out}")

    sys.exit(1 if failed else (2 if unknown else 0))


if __name__ == "__main__":
    main()