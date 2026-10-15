# aws-compliance-collector


## Findings (2026-10-16)
| ID | Resource | Result | Note |
|---|---|---|---|
| IAM-MFA-001 | root | PASS | No root password present (root access centrally managed by AWS Organization). Human sign-in via AWS Builder ID with MFA (TOTP + WebAuthn). |
| IAM-MFA-001 | grc-auditor | PASS | Programmatic-only; no console password, so MFA not required. Least privilege: SecurityAudit + ReadOnlyAccess only. |
| IAM-SCP-001 | account | INFO | Member of AWS-managed Organization; SCP explicitly denies iam:GetLoginProfile. Collector uses the IAM credential report as primary evidence. |