# Lifecycle orchestration validation

## Readiness repair validation — 2026-11-09

Execution checkout: `E:\AI\enterprise_ai_platform`. No deployment, Terraform
plan/apply, IAM mutation, HCP setup change or workflow dispatch was performed.

| Check | Result |
| --- | --- |
| Focused lifecycle, IAM handoff, historical IAM preservation, setup/recovery and teardown regressions | PASS — 111 tests |
| Existing Terraform OPA suite | PASS — 184/184 |
| IAM binding-refresh OPA suite | PASS — 6/6 |
| Ruff check and formatting, provision modules and new regression file | PASS |
| Strict mypy, all provision modules | PASS — 12 source files |
| Bootstrap Terraform 1.16.1 validate, protected configuration | PASS |
| Bootstrap Terraform validate with the exact generated destruction overrides | PASS |
| AWS Access Analyzer, refresh plan/apply and teardown plan/apply documents | PASS — all four returned zero findings, no further pages |
| Git whitespace check | PASS |
| Owner execution of independent-role setup and HCP rebinding | NOT RUN |
| Reviewed main publication and PR checks for these repairs | NOT RUN |
| Live end-to-end deployment, release or teardown | NOT RUN |

Terraform validation used temporary copies, omitted private tfvars/state, disabled
the backend and used the cached AWS provider 6.55.0. The main source protections
were not disabled. Access Analyzer was read-only and used representative exact
storage/key ARNs; the owner helper separately revalidates actual state-derived
policy documents before setup. Zero findings are not effective-permission proof.

Regression coverage includes a partial apply's new state, preservation of failed
proof/history, wrong lineage/serial/creating run, approval races/declines, changed
bindings, active-run rejection, protected-source mode separation, exact phase trust,
no self-administration, inline-size limits, setup idempotence and no Terraform runs
from the setup helper. The initial new teardown-policy test caught an inline-size
overflow; combining statements only when their scope and conditions are identical
resolved it without broadening resources or actions. Final tests passed afterward.

The read-only readiness audit remains distinct from this implementation: AWS login
and HCP remote/non-auto-apply settings were verified then, but the independent
bootstrap role bindings still require owner execution. See
[owner commands and remaining publication steps](deployment-readiness-repairs.md).

## Earlier validation — preserved historical record

Date: 2026-10-30. Execution checkout: `E:\AI\enterprise_ai_platform`.
Python: the existing project Python 3.13 environment. OPA: local 1.20.0.

This is local implementation evidence. It does not certify a successful live
deployment, application release, rollback, teardown, IAM authorization or billing closure.

## Results

| Check | Result |
| --- | --- |
| New lifecycle unit, contract, security and teardown tests | PASS, 42 tests |
| Existing release contract, integration, feature, CLI, rollback and cleanliness tests | PASS, 113 tests |
| Combined run of those two groups | PASS, 155 tests |
| Existing capstone unit, initial-state, release-security, initial-plan OPA, lifecycle-security and Terraform module-contract regressions | 862 PASS in the final broad run; the remaining protected-file hash test PASS on targeted rerun after restoring committed LF bytes |
| Repository-wide Ruff lint | PASS |
| Repository-wide Ruff formatting | PASS, 734 files in the final check |
| Full configured strict mypy scope | PASS, 210 source files |
| Focused strict mypy scope | PASS, 9 provision modules |
| Git whitespace check | PASS |
| Both CLI help entry points | PASS; no service connection |
| Live HCP/GitHub/AWS/Kubernetes execution | NOT RUN |
| Live application VERIFIED release / rollback / teardown | NOT RUN |

The 863 broad regression cases all have passing results after the targeted rerun;
this is not represented as a single uninterrupted all-green batch. No tests were
disabled or assertions relaxed. No pre-existing historical proof was upgraded.

## What the tests cover

- Canonical context integrity, external active/completed boundaries, expiry,
  prohibited secret fields and safe archive behavior.
- Missing-variable approval, readback, repeat-run idempotence and preserving
  existing mismatched variables for owner review.
- HCP write-ahead journals, uncertain POST recovery without duplicate runs,
  no-change completion, plan-only/resume, exact approval, state/run changes during
  approval or cleanup, and applied-state lineage/serial checks.
- Immutable image binding, ambiguous dispatch handling, SNS confirmation gating,
  and retaining protected GitHub approval for the owner.
- No VERIFIED claim for a failed/waiting workflow or missing publication artifact.
- Retained IAM/S3/KMS boundaries, rejection of unexpected dependency deletes,
  parent-first ECR image purge and error handling.
- Real OPA acceptance of the exact capstone activation gate during approved
  destroy, with negative address/type cases. Existing policy and release suites
  exercise the reused governance contracts.

Cloud write paths use mocks. Real subprocess checks are local Git/OPA/CLI checks.
The initial restricted-shell OPA launch failed with Windows process error 623;
the same authorized offline tests passed with subprocess execution available.

## Validation corrections

The first broad run reported 12 failures. Twenty unchanged Terraform files had
CRLF bytes while their committed blobs and `.gitattributes` required LF. Two
protected test files had the same issue. Only files whose LF-normalized bytes
exactly equaled `HEAD` were restored to those committed bytes; Terraform semantics
and protected hash expectations were not changed. These restorations produce no
content diff. `prepare` now detects this condition early.

One test also correctly rejected a test-evidence directory inside the repository.
The corrected broad run used pytest's external temporary directory. The last
protected-file hash test was then rerun successfully after the two test-file byte
restorations. An intermediate isolated Git snapshot was used only for offline
source-binding diagnosis; it was never an operational source or a deployment.

## Operational limits

- Reviewed code must be merged and synchronized to clean main before execution.
- Owner inputs, retained bootstrap/IAM, usable credentials and an exact uploaded
  VCS configuration version remain prerequisites. Missing/ambiguous versions stop.
- Existing encrypted GitHub secrets can be verified only for presence locally;
  their effective identity is checked when the workflow uses them.
- Setup inspection is workspace/repository scoped. Inherited variable sets,
  environment overrides, enterprise rules and future AWS permissions are not
  exhaustively simulated.
- A non-NOOP rollback requires an owner-bound rollback record and prior VERIFIED
  lineage. The tool does not select an arbitrary image or fabricate that lineage.
- Native reconciliation covers reviewed primary resources. Orphan discovery,
  retained storage costs, KMS deletion delays and delayed billing remain explicit
  follow-up boundaries.

No HCP plan/apply, workflow dispatch, AWS/Kubernetes mutation, registry push,
main-checkout commit or remote push was performed during this implementation task.


## Six IAM gap corrections — 2026-11-01

This is a separate validation record for the approved G1–G6 changes. Earlier
counts above describe the prior lifecycle implementation, not this test batch.

| Check | Result |
| --- | --- |
| Focused IAM handoff, incident preservation, ownership, lifecycle, teardown and Terraform contract/security pytest suites | PASS: 122 tests |
| Existing Terraform OPA suite | PASS: 184/184 |
| New IAM binding-refresh OPA suite | PASS: 6/6; added to infrastructure-policy CI |
| OPA strict policy check | PASS |
| Terraform 1.16.1 fmt and backend-disabled validation of bootstrap/sandbox | PASS |
| TFLint 0.60.0 with pinned AWS ruleset 0.48.0, both roots | PASS |
| Ruff check/format, changed Python and provision modules | PASS |
| Strict mypy | PASS: 10 provision modules |
| Actionlint 1.7.12, edited CI workflow | PASS |
| Checkov 3.3.16, candidate infrastructure source without private tfvars | PASS: 510 passed, 0 failed, 32 existing skips |
| Checkov, committed HEAD infrastructure baseline | PASS: 510 passed, 0 failed, 32 existing skips |
| Checkov, owner checkout including private auto.tfvars | FAIL: 510 passed, 1 failed, 32 skips; CKV_AWS_339 on EKS version |
| Live IAM simulation, HCP plans/applies, deployments, imports or AWS mutations | NOT RUN |

The private `infra/environments/sandbox/terraform.auto.tfvars` selects EKS `1.36`.
The EKS module/version declaration is unchanged. The owner input and scan
exceptions were left untouched. Source-only scans used isolated validation copies
outside the checkout, never deployment sources; they omitted private tfvars.
The owner-inclusive finding remains open rather than being represented as PASS.

The preservation fixture binds 19 historical HCP policy/trust documents and all
16 HCP managed-policy attachment edges. It allows only the approved exact
mandatory-tag restriction for the default SG. Additional tests cover workload
Public ECR/OIDC/EKS/KMS controls, future physical IDs, absent/expired bindings,
wrong role trust, incomplete/denied simulations, unexpected actions/resources,
source-state races and bootstrap-state changes. Simulation is an owner-execution
preflight, not complete service-context authorization proof.

Static validation initially exposed absent owner-binding keys to TFLint; empty
sentinels now allow inspection while Terraform validation still rejects missing
required deployment bindings. The source-state identity is also recorded as a
bootstrap output. No captured physical ID or expired date is used as an executable
default. The pinned AWS lint plugin was installed only into an external validation
cache. Offline OPA/provider subprocesses required normal Windows execution after
sandbox DLL-relocation errors; those reruns passed.

Dedicated remote bootstrap plan/apply identities remain owner-provided external
prerequisites. No privileged execution role was created, no HCP workload role was
elevated, and no live capability claim is made. The workbook remained untouched
while open in Excel; the companion cross-check and handoff runbook record the fix.

## PR publication validation — 2026-11-09

The lifecycle package is included in the PR Ruff lint/format commands as well as
strict mypy. The existing secret-scanner configuration is unchanged. Nineteen
reviewed non-secret findings were added to its exact baseline: 18 distinct
historical policy SHA-256 fingerprints in `iam_incident_baseline.json` and the
fixed `IAM_FINALIZED_STATE_OUTPUT_REQUIRED_platform_iam_applied_bindings`
diagnostic identifier. The regression contract records their exact paths, types
and line positions; these are not credentials or live permission evidence.

Deployment remains owner-executed. This PR publication performs no deployment,
Terraform plan/apply, AWS/HCP setup mutation, or release-workflow dispatch.
