# Deployment readiness repairs — 2026-11-09

These changes are implementation and offline-test evidence, not a deployment.
No AWS/HCP setup, Terraform run, workflow dispatch, apply or teardown was executed.
HCP remains the Terraform execution authority. Work from the main tracked checkout
`E:\AI\enterprise_ai_platform`; never deploy from a Codex worktree.

## Required publication boundary

The readiness audit found the implementation on `codex/w12-bootstrap-iam-consolidation`
with uncommitted/untracked source. The clean-main guard is intentional and remains.
Review the scoped code and tests, commit/push a PR, pass quality/infrastructure-policy,
merge, and synchronize clean main before executing the commands below. Do not stage
unrelated architecture documents or ignored private inputs/evidence. This task did
not commit, push or merge. Local test success does not replace the PR checks.

## Independent bootstrap execution identities — owner execution

The audit observed the bootstrap workspace still bound to the workload HCP roles.
Those roles must not administer their own policies. The setup helper creates two
independent, owner-managed refresh identities with exact phase-specific HCP OIDC
trust. They are outside the bootstrap-managed 17-role inventory and survive its
teardown. They grant read access to the existing bootstrap objects and exact IAM
objects; the apply role additionally permits bounded policy/trust/tag refresh.
It cannot create/delete workload roles, attach policies, pass roles or build workloads.
The shared OIDC providers are retained and not altered.

The helper derives bucket/table/key identities from the current finalized bootstrap
state and the exact 17 roles/13 customer policy ARNs from tracked source. It validates
the proposed policy with Access Analyzer and enforces the inline size limit. Existing
dedicated roles with different trust, permissions boundaries, extra attachments or
different policy documents stop for review rather than being overwritten. Existing
workload roles and their incident corrections are not changed by this setup helper.

Run these sequentially **after publication** using the existing AWS SSO session and
HCP/GitHub credentials. No token entry or token printing is needed. Refresh SSO only
if the session has expired, using the existing profile.

```powershell
Set-Location -LiteralPath 'E:\AI\enterprise_ai_platform'
$python = 'E:\AI\.venvs\enterprise-ai-platform-global-py31315\Scripts\python.exe'
$setupPlan = 'E:\AI\evidence\enterprise_ai_platform\W12\setup\bootstrap-refresh-' + [guid]::NewGuid().ToString() + '.json'

# Read-only cloud inventory; writes a reviewable external setup-plan file.
& $python -B -m provision.bootstrap_authority --plan $setupPlan
if ($LASTEXITCODE -ne 0) { throw 'Setup planning stopped; inspect the sanitized result.' }

# Inspect the exact trust/policies/old HCP values in the plan file before this step.
# Creates/reuses dedicated roles, then changes only bootstrap's three AWS env variables.
& $python -B -m provision.bootstrap_authority --plan $setupPlan --apply
if ($LASTEXITCODE -ne 0) { throw 'Setup stopped; inspect the events journal before continuing.' }
```

The plan expires after one hour. The second command rederives and compares the full
plan, validates source/state/current variables, and requires `SETUP BOOTSTRAP AUTHORITY
<exact hash>`. AWS and HCP changes are journaled before submission; no mutation is
automatically retried. After a partial setup, generate a **new review plan**: matching
objects are reused, conflicts stop, and uncertain outcomes must first be inspected.
The external `.result.json` records verified bindings. Set these in the next owner
inputs file before `prepare` (never edit an active context's bound inputs):

```json
"bootstrap_execution": {
  "plan_role_arn": "arn:aws:iam::526338061652:role/enterprise-ai-bootstrap-refresh-plan",
  "apply_role_arn": "arn:aws:iam::526338061652:role/enterprise-ai-bootstrap-refresh-apply"
}
```

HCP variables changed: `TFC_AWS_PROVIDER_AUTH=true`, `TFC_AWS_PLAN_ROLE_ARN`,
`TFC_AWS_APPLY_ROLE_ARN`, environment category, non-HCL. No workspace execution-mode,
auto-apply, token, sandbox variable or Terraform configuration is changed. Keep both
workspaces remote/non-auto-apply and the mandatory Infracost task in place. Normal
`prepare` verifies those prerequisites and simulation; IAM simulation still does not
prove SCP/service-context authorization or successful live deployment.

## Partial bootstrap-apply recovery

Previously `--new-attempt` removed the failed run checkpoint but reused the old
bootstrap-state proof. A partial apply therefore stopped every retry with
`BOOTSTRAP_HANDOFF_STATE_CHANGED`.

Recovery now requires a known failed terminal run. Any changed bootstrap state must
have the same lineage, a greater serial and a creating-run relationship to that
failed run. The sandbox source state and approved target binding values must remain
unchanged. A fresh finalized bootstrap proof is read, explicitly approved by hash,
and race-checked. The previous run and its proof are preserved in recovery history.
Only then may a new HCP plan be created; OPA, Infracost and exact apply approval run
again. Active/uncertain runs, unrelated state, expired context or changed approvals
still stop. An uncertain POST resumes its original journal, not `--new-attempt`.

```powershell
# Only after a known terminal failure; $runId is the existing unexpired context UUID.
& $python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-seed --new-attempt --plan-only
# For the second binding stage use --stage bootstrap-bind-complete instead.
# Resume without --new-attempt to review/apply that exact newly created plan.
& $python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-seed
```

## Separately authorized bootstrap teardown

Ordinary sandbox teardown still retains IAM/S3/KMS. Bootstrap destruction is not a
deployment prerequisite. It requires a separate disposition for any retained sandbox
state, an empty sandbox state, independently archived evidence, and a new approval.
The refresh roles deliberately lack deletion authority.

Terraform's `prevent_destroy` is a literal source control, not a runtime variable.
The new source-preparation command generates **only** `prevent_destroy=false`
overrides for currently protected bootstrap IAM resources. It preserves every
resource address, trust/policy expression and other lifecycle rule. Normal Terraform
source remains protected until these two generated files are separately reviewed and
merged. See [HashiCorp override semantics](https://developer.hashicorp.com/terraform/language/files/override).

```powershell
# SOURCE PREPARATION ONLY: requires its own explicit typed confirmation.
& $python -B -m provision.destroy_source
```

Review and merge the two `zz_authorized_destroy_override.tf.json` files in
`infra/bootstrap/` and `infra/bootstrap/modules/platform-iam/`, then synchronize clean
main. Do not approve a VCS-generated ordinary apply. All normal deployment/release
contexts reject source containing these destruction overrides.

Only for the separately authorized destruction, use the setup commands above with
`--purpose teardown` on **both** invocations and a new `$setupPlan`. This creates
independent `enterprise-ai-bootstrap-teardown-plan` / `...-apply` roles and binds HCP
to them; it never expands the refresh roles. The extra delete authority is scoped to
the same exact retained IAM/storage/KMS inventory and current key aliases. The helper
does not purge storage or delete any infrastructure. Bind the returned teardown role
ARNs in a separate owner-input file.

```powershell
# $inputs and $approvalExpiry are the reviewed external input path and fresh UTC deadline.
& $python -B -m provision.lifecycle prepare --inputs $inputs --approval-expires-at $approvalExpiry --operation bootstrap-teardown
# Use the returned UUID as $runId. Archive path/hash and bootstrap-teardown variables
# must be supplied in the owner inputs as described in lifecycle-orchestration.md.
& $python -B -m provision.bootstrap_teardown --run-id $runId --plan-only
& $python -B -m provision.bootstrap_teardown --run-id $runId
```

The script requires the exact generated overrides in reviewed source, independent
remote role bindings, the archival proof and typed authorization. HCP still performs
plan/review/apply with exact delete targets. Owner-session S3 version/multipart cleanup
remains bounded by the reviewed plan. Do not infer immediate KMS deletion or final
billing reconciliation from Terraform completion. Independent execution roles and
OIDC providers remain explicit retained setup.

After destruction, restore source protection before any later deployment:

```powershell
& $python -B -m provision.destroy_source --restore-protection
# Review/merge the two override-file removals and synchronize main.
```

No source-preparation, setup or teardown command in this document was executed as
part of implementing the repairs. Future deployment readiness still requires the
published source, owner-executed setup and a fresh successful `prepare` report.
