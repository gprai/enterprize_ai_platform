# Sandbox log-retention exception

Owner approval recorded **2026-10-30 (Asia/Singapore)** in this conversation:

> Keep the 14-day retention and add the sandbox exception only for these two log groups.

The approval also requested local checks and documentation, with **no deployment**.

## Exact scope

| Terraform resource in sandbox | CloudWatch log group |
| --- | --- |
| `module.observability[0].aws_cloudwatch_log_group.application` | `/aws/enterprise-ai-platform/sandbox/application` |
| `module.observability[0].aws_cloudwatch_log_group.eks` | `/aws/eks/enterprise-ai-sandbox/cluster` |

Account: `526338061652`. Region: `ap-southeast-1`. Environment: **sandbox only**.
Both resources retain `retention_in_days = var.retention_days`; the sandbox
caller continues to supply `retention_days = 14`.

The exception applies only to **CKV_AWS_338**, which expects at least one year
of retention. It is implemented as one resource-local Checkov skip on each
listed block. The global scanner configuration, encryption exceptions and
separate Bedrock seven-day retention approval are unchanged.

## Reason and accepted limitation

The owner is testing a short-lived deployment and teardown cycle. Fourteen
days of application and EKS cluster logs is the accepted evidence window.
Older logs may expire and will no longer support a later investigation unless
separately preserved. This is an accepted sandbox exception, not evidence of
one-year retention or production compliance.

Re-review this decision before using the module in production, adding another
caller, or changing the approved retention purpose or duration. This record
does not authorize another resource to inherit the exception.

## Verification

- Focused security/module/IAM suite: **56 passed**.
- Tests enforce the exact two new skip locations, the sandbox-only module
  caller, 14-day retention and the unchanged Bedrock exception.
- Source-only Checkov 3.3.16: **510 passed, 0 failed, 32 skipped**, no parsing
  errors. The skip count increased by exactly two from the previous scan.
- Terraform formatting, Ruff check/format and Git whitespace checks: **PASS**.
- AWS/HCP/Kubernetes mutation, Terraform plan/apply and deployment: **NOT RUN**.
- Remote GitHub jobs: **NOT RUN**.

The source-only scan excludes private tfvars; they remain untouched. Full
validation boundaries and the earlier findings are recorded in
[IAM-VALIDATION.md](../../bootstrap/IAM-VALIDATION.md). The sealed historical
deployment-record package was not rewritten.
