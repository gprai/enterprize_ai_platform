# Platform IAM consolidation validation

Recorded 2026-10-30. Source validation preceded the migration; the exact
owner-executed 66-object adoption subsequently completed successfully.

The owner approved moving all 17 platform roles and their policies into
bootstrap. Work was performed in `E:\AI\enterprise_ai_platform`. AWS access
was read-only, using the existing SSO profile. No credentials were copied into
the repository.

## Inventory and ownership coverage

- Live inventory: **17 roles, 13 customer-managed policies, 16 inline policies,
  and 20 role-policy attachments**. Four distinct attached policies are owned
  by AWS and remain referenced by ARN.
- Bootstrap import coverage: **66 unique objects**, with exact import IDs.
- Sandbox transfer coverage: **31 objects**, using `removed` blocks with
  `destroy = false`. Their replacement data sources read the retained roles.
- The existing 15 workload role definitions and policy expressions were moved
  into `modules/platform-iam`; the two HCP execution roles and their manually
  repaired permissions were captured from AWS.
- The original capture validation rendered all HCP policy/trust templates with
  the captured bindings and compared their complete documents with the live
  snapshot. The current tracked tests render every operational template and
  validate the complete manifest and import coverage without depending on the
  ignored capture evidence. All 23 captured-file hashes were reverified after
  separating source from evidence. No IAM permission expansion was introduced.
  The two log-retention exceptions below were separately approved by the owner
  on 2026-10-30.
- All IAM resources and attachment declarations in bootstrap use
  `prevent_destroy`. Shared OIDC providers, SSO roles and service-linked roles
  remain outside this ownership transfer.

## Checks actually completed

| Check | Result |
| --- | --- |
| Terraform 1.16.1 formatting, recursively under `infra` | PASS |
| Bootstrap `terraform validate`, backend disabled | PASS |
| Sandbox `terraform validate`, backend disabled | PASS |
| TFLint 0.60.0, bootstrap and sandbox | PASS |
| Focused IAM, release, module, policy and initial-state tests | 234 PASS |
| Additional feature tests and exact Terraform file-inventory tests | 6 PASS |
| Retention-exception follow-up: scoped security, module and IAM regression tests | 56 PASS |
| Ruff and Git whitespace checks | PASS |
| Checkov 3.3.16, source-only candidate after approved exceptions | **PASS: 510 passed, 0 failed, 32 skipped**, no parsing errors |
| Remote GitHub quality/infrastructure-policy jobs | NOT RUN |
| Terraform plan, import, state transfer or apply at source-validation time | NOT RUN; subsequently completed through the exact owner-executed adoption |
| Live deployment or teardown | NOT RUN |

Validation and TFLint used external local provider/plugin caches. They did not
initialize the HCP backend or query AWS resource state. The focused tests were
offline. The test session's generic “Running teardown with pytest sessionfinish”
message is not a cloud teardown action.

The exception follow-up reran Terraform formatting, Ruff check/format, the
56-test focused suite, the source-only Checkov scan, and Git whitespace checks.
The earlier Terraform validation and TFLint results above are retained; they
were not rerun for these comment-only Terraform changes. No backend or cloud
operation was needed for this follow-up.

### Owner-approved sandbox retention exceptions

The initial source-only scan failed `CKV_AWS_338` for:

- `module.observability.aws_cloudwatch_log_group.application`
- `module.observability.aws_cloudwatch_log_group.eks`

That historical result was **510 passed, 2 failed, 30 skipped**. The owner then
explicitly approved retaining **14 days** and adding the sandbox exception to
exactly these two resources. The final scan is **510 passed, 0 failed, 32
skipped**. These two results are accepted exceptions, not 365-day compliance.

Each resource now carries its own `CKV_AWS_338` comment. No global skip or
soft-fail setting was changed. Tests bind the new exception to these two blocks,
the sandbox-only caller and its 14-day input. The separately approved seven-day
Bedrock exception and all other resources remain unchanged. See the
[approval and risk record](../modules/observability/RETENTION-EXCEPTION.md).

A scan directly against the working checkout additionally reported
`CKV_AWS_339` for the EKS Kubernetes version. That scan included the owner's
private `terraform.auto.tfvars`; the source-only comparison excluded it and
did not report that finding. The private file was preserved, not edited or
included in the inventory. This separate version finding was not waived or
retested against the private inputs during the retention follow-up. Neither
scan proves live AWS authorization. Remote CI has not been run.

## Deployment boundary and completed adoption

Follow [IAM-MIGRATION.md](IAM-MIGRATION.md) for the ownership model and retained
execution-authority constraints. The completed adoption imported 66 objects,
verified all destination addresses, returned the adoption flag to `false`, and
ended with a zero-change normal bootstrap plan. Bootstrap state is now
`sv-q5CVPYCbwFBV9U1m`, serial 4. This completed migration does not authorize a
future provisioning; captured expiry values and generated resource IDs remain
historical bindings.

The existing [deployment record package](../../docs/deployment-records/README.md)
and its sealed hashes were preserved. Group 3 remains parked with its prior
failure and local token fix recorded. No commit, push, workflow dispatch,
rollback or teardown was performed.
