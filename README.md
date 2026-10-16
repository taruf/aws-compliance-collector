# aws-compliance-collector

Automated evidence collection for AWS compliance audits — the kind of proof auditors ask for (SOC 2, ISO 27001, SAMA CSF, and friends) without the usual ritual of screenshotting the IAM console at 11pm before a deadline.

## Why this exists

Every audit cycle asks the same questions: *is MFA enforced? who has console access? is logging enabled?* The answers live in AWS, but proving them usually means manually clicking through the console, exporting a credential report, and pasting screenshots into a spreadsheet — repeated every quarter, for every account.

This project turns those checks into scripts: point one at an AWS profile, get back a timestamped, machine-readable evidence file mapped to the relevant control IDs. Re-run it on a schedule and you have a running audit trail instead of a scramble.

## What it checks today

| Check | Script | Controls |
|---|---|---|
| MFA enabled for root and all console-enabled IAM users | [`checks/iam_mfa.py`](checks/iam_mfa.py) | SOC 2 CC6.1 · ISO 27001:2022 A.5.17 / A.8.5 · SAMA CSF 3.3.5 · NCA ECC 2-2 |

More checks (password policy, access key age, S3 public access, CloudTrail coverage, etc.) are easy to add following the same pattern — see [Adding a new check](#adding-a-new-check).

### How the MFA check works

1. **Root — always live.** Root's MFA status is checked every run via `get_account_summary`, which is never cached, so enabling root MFA is reflected immediately instead of waiting out the credential report's cache window.
2. **Everyone else — IAM credential report, primary source.** One `generate_credential_report` / `get_credential_report` call covers every other IAM user in a single pass. This is the standard auditor artifact.
3. **Fallback — per-resource API calls.** If the credential report is unavailable (or denied), the script falls back to `list_users`, `get_login_profile`, and `list_mfa_devices` for everyone but root.
4. **Nothing is silently passed.** Service Control Policies in an AWS Organization can deny some of these reads for a scoped-down auditor role. When that happens the affected resource is reported as `UNKNOWN` with the reason, rather than quietly counted as a pass or dropped from the report.

Each finding ends up as `PASS`, `FAIL`, `N/A` (no console password, so the MFA control doesn't apply), or `UNKNOWN`, and the overall result is `PASS` / `PARTIAL` (some `UNKNOWN`) / `FAIL` (at least one real failure).

Root is always evaluated against the MFA requirement regardless of whether it currently has a console password — root retains console sign-in capability (including via account recovery) even when no password is set, so it can never be marked `N/A`.

The IAM credential report used for everyone but root is cached by AWS for up to 4 hours. Each run records `credential_report_generated_at` in the evidence, so a stale `PASS` for a *non-root* user (e.g. right after enabling their MFA) is visible rather than silently trusted. Root is unaffected by this since it's always checked live.

## Getting started

### Prerequisites

- Python 3.9+
- An AWS CLI profile (or default credentials) for a **read-only auditor identity** — this tool only ever reads, it never modifies IAM state

Minimum IAM permissions for the profile you audit with:

```
iam:GenerateCredentialReport
iam:GetCredentialReport
iam:GetAccountSummary
iam:ListUsers
iam:GetLoginProfile
iam:ListMFADevices
sts:GetCallerIdentity
```

### Install

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Run it

```powershell
python checks\iam_mfa.py --profile grc-auditor
```

| Flag | Description |
|---|---|
| `--profile` | AWS CLI profile to run the check as (omit to use default credentials) |
| `--out` | Path to write the JSON evidence file. Defaults to a timestamped path under `evidence/` (e.g. `evidence/iam_mfa_2026-10-16_0806.json`) so each run keeps its own history instead of overwriting the last one — pass an explicit path to override. |

The script prints a human-readable line per finding, then a summary, and writes the same data as structured JSON to `--out`.

### Exit codes

CI-friendly by design — wire this straight into a pipeline gate:

| Code | Meaning |
|---|---|
| `0` | `PASS` — no failures, nothing unverifiable |
| `1` | `FAIL` — at least one real violation |
| `2` | Could not verify — at least one `UNKNOWN` finding (e.g. an SCP blocked a read) and no `FAIL`. Treated as distinct from a clean pass so a scope limitation never silently exits `0`. |

## Sample run

A real run against this project's own test account:

| ID | Resource | Result | Note |
|---|---|---|---|
| IAM-MFA-001 | root | FAIL | Root always requires MFA, regardless of whether a console password is currently set — no MFA device is registered. |
| IAM-MFA-001 | grc-auditor | N/A | Programmatic-only; no console password, so the MFA control doesn't apply. Least privilege: SecurityAudit + ReadOnlyAccess only. |

*(Captured 2026-10-16. Your own run will land in `evidence/`, not here — see below.)*

## Project structure

```
checks/        one script per compliance check
evidence/      generated JSON evidence (git-ignored — don't commit live account data)
requirements.txt
```

## Adding a new check

Each script in `checks/` is self-contained and follows the same shape: parse `--profile`/`--out` (default `--out` to a timestamped path so runs don't overwrite each other), collect findings with an explicit `PASS` / `FAIL` / `N/A` / `UNKNOWN` status and a `source`, map them to the relevant control IDs, and exit `1` on `FAIL` / `2` on unverifiable-but-no-`FAIL` / `0` otherwise. Copy `iam_mfa.py` as a starting template.

## A note on evidence files

Anything written to `evidence/` can contain real account IDs and identity details — it's git-ignored on purpose. Treat generated evidence like any other audit artifact: store it somewhere access-controlled, not in source control.
