# Bootstrap ownership of platform IAM

Status: **ownership migration completed; bootstrap is the active IAM state owner**.

The owner authorized moving all 17 platform roles into bootstrap. This replaces
the previous split between command-created HCP permissions and sandbox-owned
workload IAM. Group 3 remains parked. This change does not authorize a release,
rollback, teardown, workflow dispatch, or IAM deployment.

## Observed source of truth

AWS IAM was read on **2026-10-30 at 03:39:25 UTC**, using the existing
`enterprise-ai-platform-w6-004` SSO profile in account `526338061652`.
The read included role trusts, paths, session durations, tags, every inline
policy, every managed-policy attachment, and the default version of every
attached managed policy. No IAM write was performed.

- [Live permission snapshot](../../docs/deployment-records/evidence/bootstrap-iam-capture/live-2026-10-30.json): all 17 roles,
  13 customer-managed policies, 16 inline policies, and 20 attachment edges.
- [Ownership transfer map](../../docs/deployment-records/evidence/bootstrap-iam-capture/ownership-transfer.json): all 66 destination
  addresses and import IDs, including the 31 objects currently owned by sandbox.
- [Captured bindings](platform-iam-config/bindings.captured.json): historical exact IDs
  and times. These values are evidence, **not fresh deployment approval**.
- [HCP resource manifest](platform-iam-config/hcp-resources.json): the two HCP roles,
  13 managed policies, four inline policies, and 16 attachments formerly created
  through owner commands.
- [Policy templates](platform-iam-config/): preserve the observed HCP permission documents;
  only named, exact resource bindings can be substituted.

The operational manifest, bindings, and templates are tracked Terraform source
under `platform-iam-config`. The ignored `docs/deployment-records/evidence`
location contains capture and migration evidence only; bootstrap does not read
those evidence files while planning or applying.

The four AWS-managed policies are attached by ARN. Their AWS-owned documents are
captured for evidence, not copied into customer-managed replacements. SSO roles,
AWS service-linked roles, Control Tower roles, and unrelated account roles are
outside this transfer. The existing HCP and GitHub OIDC providers remain under
their existing ownership. Bootstrap reads them rather than importing a shared
provider or creating a duplicate.

## Ownership after migration

| Role | Bootstrap resource |
| --- | --- |
| `enterprise-ai-capstone-hcp-plan` | `aws_iam_role.hcp["enterprise-ai-capstone-hcp-plan"]` |
| `enterprise-ai-capstone-hcp-apply` | `aws_iam_role.hcp["enterprise-ai-capstone-hcp-apply"]` |
| `enterprise-ai-capstone-build` | `module.platform_iam.aws_iam_role.capstone_build` |
| `enterprise-ai-capstone-codebuild` | `module.platform_iam.aws_iam_role.capstone_codebuild` |
| `enterprise-ai-capstone-deploy-caller` | `module.platform_iam.aws_iam_role.capstone_deploy_caller` |
| `enterprise-ai-capstone-rollback-reader` | `module.platform_iam.aws_iam_role.capstone_rollback_reader` |
| `enterprise-ai-capstone-pki-bootstrap` | `module.platform_iam.aws_iam_role.capstone_pki_bootstrap` |
| `enterprise-ai-platform-sandbox-github-oidc` | `module.platform_iam.aws_iam_role.github_oidc` |
| `enterprise-ai-sandbox-runtime` | `module.platform_iam.aws_iam_role.runtime` |
| `enterprise-ai-sandbox-ingestion` | `module.platform_iam.aws_iam_role.ingestion` |
| `enterprise-ai-sandbox-opensearch-admin` | `module.platform_iam.aws_iam_role.opensearch_administrator` |
| `enterprise-ai-sandbox-fis` | `module.platform_iam.aws_iam_role.fis` |
| `enterprise-ai-sandbox-cluster` | `module.platform_iam.aws_iam_role.cluster` |
| `enterprise-ai-sandbox-node` | `module.platform_iam.aws_iam_role.node` |
| `enterprise-ai-sandbox-bedrock-log-delivery` | `module.platform_iam.aws_iam_role.bedrock_log_delivery` |
| `enterprise-ai-w12-prerequisite-image-publisher` | `module.platform_iam.aws_iam_role.w12_image_publisher` |
| `enterprise-ai-w12-public-ecr-reader` | `module.platform_iam.aws_iam_role.w12_public_ecr_reader` |

The existing workload IAM implementation has moved to
[`modules/platform-iam`](modules/platform-iam). Its permission statements and
trust restrictions are retained. The EKS cluster/node roles, their four
AWS-managed-policy attachments, and the Bedrock log-delivery role/policy are
included there. All 15 workload roles are now provisioned by bootstrap, even
before EKS or capstone activation.

Sandbox's IAM module now reads these roles. The EKS and observability modules
also read their existing roles. Sandbox still owns EKS access entries,
Pod Identity associations, clusters, nodes, add-ons, CodeBuild projects,
log groups, and other workload resources. Those are not IAM roles or policies.

## Ordered adoption of the existing deployment

Perform this once, from **`E:\AI\enterprise_ai_platform`**, only after review and
separate execution authorization. Never run bootstrap and sandbox concurrently
during the ownership transfer. Do not reuse a previously saved plan or receipt.

1. Keep both workspace run queues idle. Arrange the owner-controlled rollout of
   the reviewed source so a merge-triggered run cannot apply either half of the
   migration prematurely. Record the current bootstrap and sandbox state-version
   IDs and serials. Keep the existing HCP token setup; never print the token.
2. Keep the currently enabled sandbox activation flags and all existing input
   bindings unchanged. Prepare the sandbox migration plan against its current
   state. The `iam_ownership_transfer.tf` files contain `removed` blocks with
   `destroy = false`, including the counted EKS/observability modules.
3. Review that sandbox plan. Its only managed-resource actions for this migration
   must be **31 forget operations**, with no IAM deletion, replacement, or
   workload creation/update. If an expiry gate requires refreshed inputs, review
   that resulting delta separately; do not label it an import-only migration.
4. Apply the exact reviewed sandbox migration plan after owner authorization.
   Record the resulting state identity. Verify that the 31 `from` addresses in
   the transfer map are absent from sandbox state and that the live roles remain.
   State ownership has changed; AWS IAM has not been deleted.
5. Set bootstrap's Terraform input `adopt_existing_platform_iam = true` for the
   adoption run. Preserve the captured IAM binding values for an identity-only
   adoption. Prepare the bootstrap import plan against its current state using
   [`platform_iam_imports.tf`](platform_iam_imports.tf). It lists all **66** exact
   imports, including the command-created HCP policies and inline policies.
6. Review the bootstrap plan: require 66 imports, no IAM create/delete/replace,
   and no unreviewed permission or trust changes. Import can reveal defaults or
   live drift; resolve those differences explicitly rather than automatically
   overwriting them. Apply only the reviewed plan after owner authorization.
7. Record both final state identities. Confirm all 66 destination addresses are
   now in bootstrap and none of the 31 old addresses remain in sandbox. Turn off
   `adopt_existing_platform_iam` for subsequent provisioning. It defaults to
   `false`; resources remain managed when the import switch is disabled.
8. Run normal owner-reviewed plans for both roots before resuming deployment.
   Preserve the import/removal declarations and transfer map as migration history.
   Reissue source-bound release records/OPA receipts when the parked release is
   resumed; records from the pre-migration source must not authorize this change.

Terraform supports this state transfer using
[non-destructive removed blocks](https://developer.hashicorp.com/terraform/language/block/removed)
and [conditional import blocks](https://developer.hashicorp.com/terraform/language/block/import).
The files do not execute a migration merely by being present on disk.

## Completed adoption

The owner-executed adoption completed on 2026-10-30. The reviewed plan imported
all **66** IAM objects with no IAM create, delete, or replacement. Bootstrap
state advanced to `sv-q5CVPYCbwFBV9U1m`, serial **4**; all destination addresses
were verified, `adopt_existing_platform_iam` was returned to `false`, and the
normal flag-off plan reported zero managed changes. The local bootstrap state
file and workspace execution mode were restored after the isolated adoption.

The local evidence record is
`docs/deployment-records/evidence/bootstrap-iam-adoption-20261030T061646Z.json`
with SHA-256
`013c16579047c38eb141c4ed383cdca4733b386d6408d349bd6ced7a4bb63e91`.
That evidence directory is intentionally ignored; the operational Terraform
configuration under `platform-iam-config` must remain tracked.

### Bootstrap authority is an explicit prerequisite

The retained HCP apply role is deliberately **not granted permission to rewrite
its own trust or expand its own policies** by this change. Provisioning or
updating bootstrap-owned IAM therefore requires the existing owner-controlled
administrative identity, such as the approved SSO session. An HCP team token
authorizes HCP operations; it is not an AWS administrator credential.

Do not run this new bootstrap IAM plan under the old HCP execution roles and
assume it can succeed. A remote HCP run does not inherit the terminal's SSO
session. Select an explicitly authorized owner execution path (for example,
owner-local execution connected to the same bootstrap state with the required
private inputs) before adoption/provisioning. Changing the workspace execution
mode or injecting AWS credentials is not performed or authorized by this patch.
No new static AWS keys are required or included.

## Repeat provisioning after sandbox teardown

1. Retain bootstrap state, the 17 roles, IAM policies, OIDC providers, GitHub
   settings, and HCP settings as requested. The IAM resources and attachments
   have `prevent_destroy = true`. Sandbox teardown no longer deletes them.
   A full bootstrap destroy is intentionally blocked while this IAM remains.
2. Bootstrap creates missing roles/policies/attachments when run without the
   adoption flag. Existing bootstrap state reconciles managed IAM drift.
   Do not import resources that do not exist into an empty account/state.
3. Refresh owner-approved IAM bindings in bootstrap before workload use. The
   old dates in the capture must not be treated as current authorization.
   `platform_iam_binding_overrides` controls administrator trust expiry,
   workload permission/tag expiry, administrator role, the Bedrock model, and
   exact sandbox KMS/network identities. `platform_iam_tags` retains the approved
   seven non-expiry workload tags. HCP-role tags remain as observed.
4. The bootstrap KMS key ARN is derived from `aws_kms_key.terraform_state`.
   Sandbox KMS, VPC, route table, subnets and security groups have generated IDs.
   A fresh sandbox recreation changes them. Provision its prerequisite
   resources through the separately reviewed stage, read their actual IDs,
   update bootstrap's exact bindings, and apply that reviewed IAM delta before
   continuing dependent ECR, endpoint, EKS, or service provisioning.
   **The captured IDs are not a promise of a one-pass deployment into a new VPC.**
5. Refresh both roots' governance inputs deliberately. Changing sandbox
   `approval_expires_at`, `mandatory_tags`, or `bedrock_model_id` now affects
   workload resources only; it does not update bootstrap-owned IAM. The owner
   must keep bootstrap IAM bindings aligned with the approved sandbox inputs.
6. Plan/apply sandbox using the retained roles. IAM existence does not prove all
   service authorization paths or a deployment work; successful live execution
   remains distinct from static validation and policy-document preservation.

The standard per-role attachment resources manage only the listed edges.
They do not detach unrelated AWS-managed-policy users/roles or silently delete
unexpected extra attachments. Compare a fresh IAM inventory with the ownership
map when resolving such drift; review removals separately.

## Preserved failures and validation boundary

The earlier `GH_TOKEN_REQUIRED` application-release failure and successful
Order 7/8/9 deployment history remain in
[`docs/deployment-records`](../../docs/deployment-records/README.md).
This IAM migration does not mark Group 3 deployed or live validation complete.
Rollback and teardown remain pending the owner's instruction.

See [IAM-VALIDATION.md](IAM-VALIDATION.md) for the checks actually executed.
