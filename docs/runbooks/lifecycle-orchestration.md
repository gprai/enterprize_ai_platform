# HCP-centered deployment, release and teardown

Implementation status: local code and offline tests; not a live deployment certification.
The owner runs these commands from `E:\AI\enterprise_ai_platform` on clean,
reviewed `main`. No Codex worktree or visualization-folder script is an execution
source. Merge and synchronize reviewed code before operational use.

## Execution authority

| Work | Executor | Authority/evidence |
| --- | --- | --- |
| Source/setup inventory and local context | Owner Python process | Protected main, HCP/GitHub API readback |
| Infrastructure plan, apply and destroy | HCP remote workspace | Exact configuration, run, plan hash and state version |
| Infracost | HCP mandatory post-plan task | Exact task result bound to the run |
| OPA | Owner's checksum-bound OPA 1.20.0 | Tracked policy, no waivers, in-memory plan |
| Prerequisite image publication | Existing protected GitHub workflow | Successful exact-main run plus ECR digest readback |
| Metrics server, certificate/trust managers and PKI | Owner Kubernetes/Helm commands | Explicit temporary EKS kubeconfig, tracked pinned inputs |
| Application build, scan, attestation and publication | Existing capstone GitHub workflow | Governed record and receipt; protected approval |
| Application deployment | CodeBuild launched by that workflow | Tracked source bundle, VERIFIED publication chain |
| ECR purge before destroy | Owner AWS session | Exact reviewed repositories, bounded deletion and relisting |

There is no local Terraform plan/apply/destroy subprocess. HCP remains the
infrastructure execution and state authority. The local process orchestrates it;
it does not replace it. Local AWS SSO is used for readback, approved Kubernetes
prerequisites and bounded cleanup. HCP uses its configured dynamic AWS roles.

## Modules

- `provision/lifecycle.py`: owner CLI, context integrity, approvals, stage ordering,
  workflow handoff and evidence.
- `provision/services.py`: existing token discovery, bounded API requests and pagination.
- `provision/setup.py`: setup inventory and separately approved creation of missing setup.
- `provision/hcp.py`: non-auto-apply HCP runs, plan review, exact approval, apply and state proof.
- `provision/bindings.py`: publication, current storage/KMS, EKS issuer and probe bindings.
- `provision/kubernetes.py`: explicit-cluster pinned prerequisites and PKI readiness.
- `provision/cleanup.py`: retained-resource boundary, ECR/S3 cleanup and reconciliation.
- `provision/bootstrap_teardown.py`: separately authorized bootstrap destruction.

## Credentials and owner inputs

Keep credentials out of the inputs file and repository. HCP token lookup is:
`TFC_TOKEN`, `TF_TOKEN_app_terraform_io`, then existing Terraform CLI credentials
under the user's home or APPDATA. GitHub uses `GH_TOKEN`, `GITHUB_TOKEN`, then
`gh auth token`. No command prints a token or asks you to paste it into chat.
Missing credentials stop with a setup error; supply them through the existing
IDE secret environment. Workflow HCP secrets require a team service identity.
The CLI cannot read back encrypted GitHub secret values; the workflow validates
identity when using them. A secret's presence is not proof of its correctness.

Use an external JSON input file with schema `enterprise-ai.lifecycle-inputs.v1`.
The example in `lifecycle-inputs.example.json` is a structure guide, not an
approved or executable configuration. Supply current owner-approved values.
It includes:

- `aws_profile`; `opa.path` and verified executable `opa.sha256`.
- `common_variables`: complete typed Terraform values, including mandatory tags,
  approval issue/expiry, owner identity/cost bindings and pinned artifact inputs.
  These become run-scoped values, not workspace-variable overwrites.
- `stages.<name>.variables`: explicitly approved stage-specific overrides. Include
  base, foundation, pki-access, pki-disable, activation, release-plan and teardown.
- `hcp_variables.bootstrap|sandbox.<name>`: optional missing setup specifications
  with `category`, `hcl`, and either `value` or `from_env`. Use `from_env` for secrets.
- `github_variables.<name>` and `github_secrets.<name>`: missing setup values;
  secret entries accept only `from_env` references.
- `vcs_connection`: existing owner-authorized HCP GitHub app or OAuth connection,
  only needed to create missing workspaces. No new organization/account is created.
- `infracost_task_id`, `main_protection`, `sandbox_protection`: exact owner setup
  when missing. The Infracost integration itself must already exist.

Prepare checks both retained workspace identities and their state, remote mode,
non-auto-apply, Terraform version, VCS repository/main/root directory and project.
It also checks exact policy-bound Terraform source bytes against the commit;
Git's clean status alone can conceal CRLF/LF differences. A mismatch stops before
setup writes or HCP run creation, without weakening the reviewed-source check.
It enumerates required no-default Terraform declarations and workflow variable/
secret references. Existing values are retained; supplied expected values are
compared. Missing authoritative inputs are reported, not guessed. Missing setup
is created only with `--setup-missing` and a per-action confirmation.

The current audit is workspace/repository scoped. Inherited organization variable
sets, environment-scoped overrides and enterprise ruleset details require owner
review; the tool does not claim to resolve every precedence rule or prove that
future AWS API calls are authorized. Existing mismatched controls stop rather
than being silently rewritten. GitHub plan restrictions cannot be fixed by a token.

## Owner command sequence

For repeat provisioning after sandbox teardown, first follow the
[bootstrap IAM handoff](bootstrap-iam-handoff.md). Dedicated remote bootstrap
execution roles and fresh owner bindings are mandatory prerequisites.

From the main checkout with the project Python environment active:

```powershell
Set-Location -LiteralPath 'E:\AI\enterprise_ai_platform'
python -B -m provision.lifecycle prepare `
  --inputs 'E:\AI\evidence\enterprise_ai_platform\W12\lifecycle-inputs.json' `
  --approval-expires-at '<owner-approved UTC timestamp>'
```

Use the returned UUID as `$runId`. For approved missing setup add
`--setup-missing`. For an expired AWS session add `--login`; the command asks
before activating AWS SSO. Existing current sessions are reused.

```powershell
python -B -m provision.lifecycle provision --run-id $runId --stage identity-seed
python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-seed
python -B -m provision.lifecycle provision --run-id $runId --stage network-seed
python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-complete
python -B -m provision.lifecycle provision --run-id $runId --stage base
python -B -m provision.lifecycle provision --run-id $runId --stage images
python -B -m provision.lifecycle provision --run-id $runId --stage foundation
python -B -m provision.lifecycle provision --run-id $runId --stage bindings
python -B -m provision.lifecycle provision --run-id $runId --stage pki-access
python -B -m provision.lifecycle provision --run-id $runId --stage prerequisites
python -B -m provision.lifecycle provision --run-id $runId --stage pki-disable
python -B -m provision.lifecycle provision --run-id $runId --stage activation
python -B -m provision.lifecycle release --run-id $runId
```

Run sequentially; wait for each stage's successful checkpoint. These are the
three deployment commands, with explicit provision stages to expose meaningful
approval boundaries. They are not a single unattended deployment.

1. **Base:** sandbox prerequisites with foundation/capstone/PKI access disabled.
   Bootstrap and its adopted IAM are retained prerequisites, not recreated here.
2. **Images:** verifies publication storage from current HCP outputs and AWS KMS;
   asks before changing storage GitHub bindings; dispatches protected prerequisite
   image publication. Approve GitHub's sandbox environment when requested. Resume
   the same stage to collect exact immutable ECR digests. If the dispatch response
   lacks an ID, pass `--publication-run-id <existing-run-id>`; do not dispatch again.
3. **Foundation:** EKS and observability enabled; capstone/temporary access disabled.
   Confirm new SNS subscription emails yourself; the tool cannot approve emails.
4. **Bindings:** owner approves the live EKS issuer and reuse of the reviewed
   CodeBuild image as the immutable probe image. Both SNS email subscriptions must
   match the foundation plan's endpoints and be confirmed first. No guessed image or issuer.
5. **PKI access:** HCP plan/apply enables only the intended temporary access flag.
6. **Prerequisites:** explicit-cluster Metrics Server, cert-manager, trust-manager,
   namespaces, service accounts, token-review RBAC, root ceremony, certificate and
   trust bundle. Mirrors pinned images into the approved existing API repository.
   Waits for readiness before recording proof and binding public certificate hashes.
7. **PKI disable:** requires prerequisite proof and a plan containing only the two
   temporary access deletions (or no changes). Unexpected changes stop for review.
8. **Activation:** HCP activates the CodeBuild project/log group/access resources.
9. **Release:** creates a final infrastructure plan and real OPA receipt, dispatches
   the existing protected release workflow, and observes it on subsequent calls.
   REQUESTED -> READY_FOR_OWNER -> APPROVED -> APPLIED -> VERIFIED happens in that
   workflow. A zero-change Terraform run is valid; it is not an application deployment.

The release command returns IN_PROGRESS while GitHub awaits approval or builds.
Repeat it to observe the same run. It never approves a protected environment for
the owner. Success requires the exact eleven-file publication artifact, canonical
record chain and S3 versioned proof, not merely a green workflow or dispatch response.
The existing workflow's deployment probe/verification remains mandatory. Broader
live acceptance tests can be deferred; the command cannot label a failed deployment
VERIFIED to accommodate that deferral.

## Recovery, approvals and expiration

HCP stages print their run ID and plan review. Owner confirmation binds the exact
plan digest. Before apply the command rechecks run/configuration/state/plan and
confirmability. Applied state must belong to that run and advance serial without
changing lineage. `planned_and_finished` is accepted only for a verified no-change
plan. Raw plan/state can be read in memory, but are not written to evidence.

`--plan-only` on HCP provision/teardown stages reviews without apply. Resume the
same command without it to approve that saved plan. `--new-attempt` is allowed
only for a known failed/canceled/discarded terminal run, and preserves its history.
It is not a retry of an uncertain POST. The journal is written before run creation,
apply and workflow dispatch; uncertain outcomes are reconciled by reads.

Contexts live under `E:\AI\evidence\enterprise_ai_platform\W12\active\<uuid>`.
Their lifetime ends at the owner approval deadline, never later than 24 hours.
Inputs/source hashes cannot change during a context. Expired contexts remain
readable with `status` but cannot authorize mutations. Preserve them and prepare
a fresh approved context; there is no automatic approval renewal or silent recovery
of a partial deployment into a new context. Such recovery requires owner review.

```powershell
python -B -m provision.lifecycle status --run-id $runId
```

An uploaded non-speculative VCS configuration for the exact reviewed commit is
required. If absent/ambiguous the tool stops: it does not upload unreviewed local
files or repurpose a speculative run. Let the connected HCP VCS integration ingest
the approved commit and inspect competing active runs before proceeding.

## Rollback and teardown

```powershell
python -B -m provision.lifecycle rollback --run-id $runId
python -B -m provision.lifecycle teardown --run-id $runId --plan-only
python -B -m provision.lifecycle teardown --run-id $runId
```

Rollback records NOOP only after successfully reading that the named application
Deployment, Service and probe Job are absent. It does not reinterpret an API failure
as absence. An existing workload requires an owner-bound canonical rollback
REQUESTED record and OPA receipt (`rollback_record.directory` and `sha256`), with
real prior VERIFIED lineage. The current wrapper consumes that lineage; it does
not fabricate or automatically select a rollback target. The protected workflow
performs a real rollback. Arbitrary `kubectl rollout undo` is not used.

Ordinary teardown retains all IAM/S3/KMS state resources conservatively, including
policies/encryption, to preserve bootstrap-owned IAM and canonical evidence access.
It selects other state addresses, reviews exact delete actions, purges images
(including OCI parent manifests) from exact reviewed ECR repositories, rechecks
state/run, then requests HCP destroy. Remaining images are cleared and relisted,
not used as a reason to silently skip the repository. Access errors stop safely.
No Terraform state removal or ownership transfer is performed by this tool.

HCP remaining-state inventory and selected native primary resources are reconciled.
The result explicitly leaves untracked/native orphan coverage and delayed/estimated
billing reconciliation OPEN. It is not zero-cost or universal no-residue proof.
Retained evidence storage can continue to incur costs. Successful teardown archives
the context, including nested receipts, under `completed/<uuid>`.

For separately authorized bootstrap teardown, prepare a fresh context with the
same reviewed source and an independently archived evidence bundle supplied as
`bootstrap_destroy_archive.path` and `sha256`, plus `stages.bootstrap-teardown`:

First follow the [reviewed destruction-source and independent execution-role
procedure](deployment-readiness-repairs.md#separately-authorized-bootstrap-teardown).
The fresh context must use `prepare --operation bootstrap-teardown`. The exact
reviewed destruction overrides are required; normal deployment contexts reject them.

```powershell
python -B -m provision.bootstrap_teardown --run-id $runId --plan-only
python -B -m provision.bootstrap_teardown --run-id $runId
```

This requires an empty sandbox state and separate typed authorization to destroy
bootstrap IAM/storage. Therefore retained sandbox evidence must first have its own
separately approved disposition; this command will not silently delete or forget it.
Bootstrap HCP must have usable dynamic execution credentials, Infracost, and a plan
that passes OPA. Destroying execution roles can affect an in-progress remote run;
independent administrative execution access must be arranged beforehand. The tool
fails closed instead of switching to local Terraform. Reviewed bootstrap S3 versions,
delete markers and multipart uploads are purged before apply. KMS deletion scheduling
and delayed bills are not treated as immediate physical absence or final reconciliation.

## Logs and evidence

Every invocation writes sanitized result JSON under `report/<uuid>/`; prepare uses
`report/setup/`. API events under `report/service-events/` include time/service/method
and phase, never headers, bodies, credentials or raw subprocess output. Reports are
ignored by Git. Domain failures have stable codes; SDK/unknown failures are classified
INDETERMINATE, with the mutation journal retained for inspection.

Deployment evidence goes to `docs/deployment-records/lifecycle/<uuid>/`; rollback and
teardown evidence goes to `docs/rollback-records/lifecycle/<uuid>/`. JSON/sidecar hashes
are immutable. Verified publication files are copied only after validation. These
directories retain their approved ignored status. Protect external inputs/evidence
with owner filesystem permissions; SHA sidecars detect corruption, not a malicious
writer who controls both files.

## Historical provenance and limits

The implementation was reconciled against the preserved Order 8/9 records, including
`docs/deployment-records/STEP-COVERAGE.md`, `04-group-2.md`, and
`docs/rollback-records/W12-001-LIFECYCLE.md`, and these historical helpers under
`C:\Users\gprai\.codex\visualizations\2026\10\20\01a15716-9187-7f33-9ea8-fe33338917ef`:

- `w12-group3-prepare-release.py`: exact REQUESTED/source/state and OPA handoff.
- `w12-group2-owner-execution.ps1`: staged prerequisites, temporary PKI access and activation.
- `w12-owner-rollback-proof.ps1`: truthful no-workload rollback NOOP.
- `w12-owner-teardown.py`: reviewed destroy, ECR purge and partial-apply recovery.

These are historical references, not invoked dependencies. Order 7's historical
superseded status and Group 3's failed predeployment history remain unchanged.
The new tool implements their forward governance boundary; offline tests do not
retroactively establish a successful release or live teardown.

Strengths: HCP remote authority, exact identities and approvals, durable uncertain-
outcome handling, no-change support, explicit Kubernetes target, retained evidence,
real release lineage, and reusable logged commands without week-named new files.

Limitations: owner input and external service availability remain necessary;
bootstrap provisioning/adoption is a retained prerequisite, not automated here;
setup is not an exhaustive inherited-permission simulator; exact VCS configuration
availability can block progress; rollback target preparation is still external;
complete orphan/billing closure requires later reconciliation; no live end-to-end
execution has been performed for this implementation.

## Local validation

`make lifecycle-orchestration-tests` runs focused unit, contract, security and teardown
tests plus Ruff and strict mypy. Service writes are mocked in tests. The real local
OPA executable is used for policy regressions when available. Existing capstone,
initial-state, lifecycle-policy and release-security tests provide regression coverage.
No tests should invoke a live plan/apply, dispatch, registry push or teardown.
See [the validation record](lifecycle-validation.md) for the measured results,
the line-ending/environment corrections, and the live checks left NOT RUN.

API contracts checked: [workspace resources](https://developer.hashicorp.com/terraform/cloud-docs/api-docs/workspace-resources)
and [state version outputs](https://developer.hashicorp.com/terraform/cloud-docs/api-docs/state-version-outputs).
Resource/output processing is asynchronous and unauthorized reads must not be treated
as empty state.
