#!/usr/bin/env python3
"""
iam_mfa.py - Evidence collector: MFA enforcement on AWS root and IAM users.

Control mapping:
  US  (SOC 2)       : CC6.1 - Logical access security / authentication
  EU  (ISO 27001)   : A.5.17 Authentication information, A.8.5 Secure authentication
  GCC (SAMA CSF)    : 3.3.5 Identity & Access Management (MFA for privileged/remote access)

Data source (in order):
  1. IAM credential report  - the standard auditor artifact (covers root + all users)
  2. Per-user API calls     - fallback if the report is blocked
  An organization SCP can deny some IAM reads. Anything we cannot verify is
  reported as UNKNOWN with the reason, never silently passed.

Usage:
  python checks/iam_mfa.py --profile grc-auditor --out evidence/iam_mfa.json

Exit code: 0 = no FAIL, 1 = at least one FAIL (CI-friendly).
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


def get_credential_report(iam):
    """Return list of rows from the IAM credential report, or raise ClientError."""
    for _ in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(2)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def evaluate(name, console, mfa, source):
    if console is None or mfa is None:
        status = "UNKNOWN"
    elif not console:
        status = "PASS"          # no console password -> MFA not required
    else:
        status = "PASS" if mfa else "FAIL"
    return {"resource": name, "console_access": console, "mfa_enabled": mfa,
            "status": status, "source": source}


def root_has_password(iam):
    """Root's password_enabled is always 'not_supported' in the report, so ask the
    account summary. Missing key => assume console access (conservative)."""
    try:
        v = iam.get_account_summary()["SummaryMap"].get("AccountPasswordPresent")
        return True if v is None else v == 1
    except ClientError:
        return True


def from_report(rows, iam=None):
    out = []
    for r in rows:
        if r["user"] == "<root_account>":
            console = root_has_password(iam) if iam else True
            out.append(evaluate("root", console, r["mfa_active"] == "true", "credential_report"))
        else:
            out.append(evaluate(r["user"], r["password_enabled"] == "true",
                                r["mfa_active"] == "true", "credential_report"))
    return out


def from_api(iam):
    out = []
    # Root: use account summary. No root password => no console login => N/A.
    s = iam.get_account_summary()["SummaryMap"]
    root_pw = s.get("AccountPasswordPresent")
    root_console = True if root_pw is None else root_pw == 1
    out.append(evaluate("root", root_console, s.get("AccountMFAEnabled", 0) == 1,
                        "account_summary"))

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
    p.add_argument("--out", default=None, help="Write JSON evidence to this file")
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile)
    iam = session.client("iam")
    account_id = session.client("sts").get_caller_identity()["Account"]

    try:
        findings = from_report(get_credential_report(iam), iam)
    except ClientError as e:
        print(f"Credential report unavailable ({_err(e)}); falling back to IAM API calls.")
        findings = from_api(iam)

    failed = [f for f in findings if f["status"] == "FAIL"]
    unknown = [f for f in findings if f["status"] == "UNKNOWN"]
    result = "FAIL" if failed else ("PARTIAL" if unknown else "PASS")

    evidence = {
        "check_id": "IAM-MFA-001",
        "title": "MFA enabled for root and all console IAM users",
        "account_id": account_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "controls": {"SOC2": ["CC6.1"], "ISO27001_2022": ["A.5.17", "A.8.5"],
                     "SAMA_CSF": ["3.3.5"]},
        "result": result,
        "summary": {"total": len(findings), "failed": len(failed), "unknown": len(unknown)},
        "findings": findings,
    }

    for f in findings:
        line = (f"[{f['status']:<7}] {f['resource']:<20} console={f['console_access']!s:<5} "
                f"mfa={f['mfa_enabled']!s:<5} via {f['source']}")
        print(line + (f"  ({f['note']})" if "note" in f else ""))
    print(f"\nRESULT: {result}  (failed={len(failed)}, unknown={len(unknown)}, total={len(findings)})")

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(evidence, fh, indent=2)
        print(f"Evidence written to {args.out}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()