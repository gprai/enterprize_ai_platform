# W12-001 IAM workbook versus bootstrap source

## Readiness follow-up — 2026-11-09

The six source corrections below remain preserved. A subsequent readiness audit
found additional execution prerequisites and recovery/teardown defects. The
[readiness repair runbook](../runbooks/deployment-readiness-repairs.md) now provides
owner commands for independent bootstrap execution-role setup, reviewed source
preparation for separately authorized bootstrap destruction, and fresh state-bound
recovery after a partial bootstrap apply. Normal `prevent_destroy` remains enabled.
No existing IAM policy/trust correction was removed or broadened by these repairs.
Independent execution identities are external setup, not additions to the adopted
17-role/66-object ownership inventory.

The [validation record](../runbooks/lifecycle-validation.md) records 111 focused
tests, both OPA suites, protected/override Terraform validation and read-only
Access Analyzer results. Owner setup, PR publication and live deployment remain
NOT RUN. This Markdown addendum does not rewrite the historical Excel findings.

## Original source cross-check — preserved

Reviewed: 2026-11-01. Checkout: `E:\AI\enterprise_ai_platform`.
HEAD observed: `cd8d3c3731ca163a3f2b738bfc7e50bec61d1948`.

## Approved correction update — 2026-11-01

The six gaps below have source corrections and offline regression coverage.
HCP remains the plan/apply and IAM mutation authority. No cloud execution was
performed. Dedicated remote bootstrap execution roles remain an owner-supplied
prerequisite; this change validates them rather than silently creating privileged
roles or elevating the workload roles.

| Gap | Implemented correction | Boundary |
| --- | --- | --- |
| G1 | New exact physical bindings come from finalized HCP seed-state outputs; captured values are not runtime defaults. | Historical capture is used only for first-refresh BEFORE comparison and regression evidence. |
| G2 | Current trust/workload deadlines are validated against the owner approval window and 24-hour maximum in Python and Terraform. | Expired inputs stop; no automatic renewal. |
| G3 | Four HCP stages implement identity seed, bootstrap seed binding, network seed and complete binding before full sandbox base convergence. | Targeted prerequisite scope is fixed; every apply still needs exact owner approval. |
| G4 | Prepare and pre-apply verify dedicated bootstrap role bindings, exact HCP trust and IAM refresh permissions. | External execution-role/provider setup is still required; no local Terraform or workload self-administration. |
| G5 | Exact default-SG tagging now requires the approved mandatory keys/values, Name and ExpiresAt. | No broader resources/actions granted. |
| G6 | Historical 19-document and attachment baseline, condition-negative tests, stale-state/expiry/scope/authority tests and dedicated OPA tests added. | Offline evidence is not complete live service authorization proof. |

See [owner handoff runbook](../runbooks/bootstrap-iam-handoff.md) and
[validation record](../runbooks/lifecycle-validation.md). The workbook remains
unchanged while open in Excel; this report preserves its original findings and
records their approved implementation status separately.

## Original cross-check conclusion (before this correction)


The historical AWS permission/trust corrections in workbook IAM-01 through
IAM-31 are represented in the current source. Their applicable role attachments
are declared. IAM-06 also depends on the sandbox-owned KMS key policy, rather
than bootstrap alone. IAM-32 ownership consolidation is implemented.

This does **not** mean a fresh deployment is ready without further work:
IAM-33 (fresh physical bindings) remains an operational gap and IAM-34
(authorization regression coverage) is only partially addressed. Expired
default bindings, bootstrap execution authority and a default-SG restriction
discrepancy are detailed below. No missing historical repair was found in the
captured HCP policy documents themselves.

This was a local source/evidence review. No AWS/HCP calls, Terraform
plan/apply/import, workflow dispatch, or deployment occurred. Current live
permissions, workspace variable overrides, quotas, boundaries and SCPs were
not examined. Defaults below are code defaults, not a claim about live inputs.

## What was cross-checked

- The workbook's 34 IAM issue rows and 22 related-blocker rows.
- Every operational HCP template against the complete retained
  `live-2026-10-30.json` IAM capture, using its original binding values:
  **19/19 exact document matches** (13 managed policies, four inline policies,
  two role trust documents).
- The manifest's **16 HCP managed-policy attachment edges**, four inline-policy
  bindings and 13 managed-policy names against that capture: exact match.
- Bootstrap's workload role definitions, Public ECR permission and immutable
  GitHub subject construction, EKS managed-policy attachments, and complementary
  bootstrap/sandbox KMS policy statements.
- All six existing functions in
  `tests/security/test_bootstrap_iam_ownership.py` executed directly offline:
  **six passed**. These are structural/ownership checks, not AWS simulation.
- Ownership declarations cover **17 roles, 13 customer-managed policies,
  16 inline-policy instances and 20 attachment edges: 66 objects**.

## Original six gaps and prerequisites (historical snapshot)

| ID | Finding | Impact | Required resolution before relying on fresh provisioning | Source |
| --- | --- | --- | --- | --- |
| G1 | Captured sandbox KMS, VPC, route-table, subnet and security-group ARNs remain fallback defaults. Overrides exist, but Terraform does not derive them from new sandbox state. | After recreation, exact-resource permissions can still authorize the previous objects, reproducing KMS-grant, parent-VPC, endpoint and default-SG denials. Workload encryption permissions also use the bound key. | Read owner-reviewed identities from the new prerequisite state and apply the exact bootstrap binding delta before dependent services. Do not widen scopes to hide this dependency. | [bindings.captured.json](../../infra/bootstrap/platform-iam-config/bindings.captured.json), [platform_iam.tf](../../infra/bootstrap/platform_iam.tf) |
| G2 | Default administrator trust expiry is `2026-10-29T14:24:44Z`; workload expiry is `2026-10-30T05:24:44Z`. Both are past at review time. Override validation checks timestamp parseability; the administrator precondition uses `can(timecmp(...))`, not a future-time comparison. | A source-valid plan can preserve expired OpenSearch/PKI administrator trust and Bedrock invocation permission conditions. Updating sandbox governance times alone does not update bootstrap IAM. | Require current owner-approved, approval-bounded bootstrap expiries and validate their relationship to the active deployment window. Explicit adoption/history handling must remain distinct from fresh provisioning. | [platform_iam_variables.tf](../../infra/bootstrap/platform_iam_variables.tf), [module main.tf](../../infra/bootstrap/modules/platform-iam/main.tf), [module variables.tf](../../infra/bootstrap/modules/platform-iam/variables.tf) |
| G3 | No bootstrap IAM binding-refresh/provision stage exists in the inspected lifecycle stage map. It contains sandbox base/foundation/PKI/activation and bootstrap teardown. The migration guide describes manual prerequisite provisioning/rebinding. | The necessary new-resource-IDs → bootstrap IAM update → dependent sandbox continuation sequence is not an implemented automatic handoff. A full base run can encounter the old bindings before dependent creates. | Implement an owner-approved, HCP-governed prerequisite and binding-update sequence, with exact-state evidence and reviewed plans, before claiming one-pass repeat provisioning. | [hcp.py](../../provision/hcp.py), [IAM-MIGRATION.md](../../infra/bootstrap/IAM-MIGRATION.md) |
| G4 | Bootstrap IAM administration requires a separately authorized AWS execution identity. The retained HCP workload roles intentionally do not manage their own roles/policies; bootstrap only reads existing HCP/GitHub OIDC providers. | An HCP token or local AWS SSO login does not supply that remote IAM authority. Bootstrap cannot create its own execution trust/provider prerequisites using these workload roles. | Keep retained providers/settings as agreed. For HCP-centred bootstrap changes, bind a separately approved bootstrap execution identity with the required read/write authority. Do not expand workload roles into self-administration. | [platform_iam.tf](../../infra/bootstrap/platform_iam.tf), [IAM-MIGRATION.md](../../infra/bootstrap/IAM-MIGRATION.md), [setup.py](../../provision/setup.py) |
| G5 | Default-SG initial `ec2:CreateTags` statement restricts the exact SG, VPC and region, but lacks the originally proposed mandatory tag-key and exact tag-value conditions. | The functional repair is present, but the documented original least-privilege proposal is not fully implemented. It permits broader tagging on that one SG. This is not a missing Allow. | Review whether to implement the omitted tag restrictions and add a specific regression assertion. Preserve the existing scope until an authorized correction is reviewed. | [network bootstrap policy](../../infra/bootstrap/platform-iam-config/enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1.json.tftpl), workbook IAM-10 |
| G6 | Ownership tests check counts, template rendering, imports and bounded overrides. They do not assert every incident's action/resource/condition/role combination. This review adds an ad-hoc capture comparison, not a committed comprehensive permission regression suite. | Tests could pass while a future edit removes SNS topic-scope read/delete, ENI discovery, FIS action scope, an attachment, or another critical repair. Static tests also cannot prove real service request context. | Add incident-based policy regression cases covering both plan and apply identities, readbacks and deletes, and supported condition/resource scopes. Keep live authorization proof separate from static checks and simulations. | [test_bootstrap_iam_ownership.py](../../tests/security/test_bootstrap_iam_ownership.py), workbook IAM-34 |

## Complete IAM issue crosswalk

Paths below are relative to `infra/bootstrap` unless noted. `config/` means
`platform-iam-config/`; `module/` means `modules/platform-iam/`. The abbreviated
policy names identify their unique template file in that directory. "Present"
means code coverage, not an executed or currently effective AWS permission.

| Workbook | Correction | Current source location / statement | Result |
| --- | --- | --- | --- |
| IAM-01 | DynamoDB KMS grant | config/*apply-bootstrap-kms-v1: `DynamoDBUseExactBootstrapKey`; bootstrap main.tf: `AllowExactAccountDynamoDBStateGrant` | Present; bootstrap key binding is derived from its resource |
| IAM-02 | DynamoDB TTL read on both roles | config/*bootstrap-dynamodb-ttl-read-v1; two attachments in hcp-resources.json | Present |
| IAM-03 | Role-create mandatory tag conditions | config/*apply-sandbox-iam-v1: `CreateExactTaggedSandboxRoles` | Present |
| IAM-04 | Publisher exact role allowlist | config/*apply-sandbox-iam-v1 and *plan-read-v1 | Present |
| IAM-05 | ECR CreateGrant | config/*apply-sandbox-iam-v1: `W12EcrCreateGrantExactSandboxKey` | Present, requires current sandbox key binding (G1) |
| IAM-06 | ECR RetireGrant and complementary key policy | config/*apply-sandbox-iam-v1: `W12EcrRetireGrantAndDescribeExactSandboxKey`; infra/modules/kms/main.tf: `EnableExactAccountKeyAdministration` includes RetireGrant | Present across bootstrap and sandbox, not bootstrap alone |
| IAM-07 | Prerequisite repository write/read scopes | config/*apply-sandbox-core-v1: `ManageExactRepository`; *plan-read-v1: `ExactRepositoryReads` | Present for all three named repositories |
| IAM-08 | Network Name/Tier tag keys | config/*apply-sandbox-core-v1: `CreateTaggedNetwork` | Present |
| IAM-09 | Parent-VPC authorization | config/*apply-sandbox-network-bootstrap-v1: `CreateNetworkResourcesInExactSandboxVpc` | Present, requires G1 |
| IAM-10 | Initial default-SG tagging | same template: `BootstrapExactSandboxDefaultSecurityGroupTags` | Functional correction present; G1 and G5 remain |
| IAM-11 | Endpoint subnet/SG/route-table/VPC authorization | config/*apply-sandbox-service-recovery-v1: `CreateVpcEndpointsUsingExactSandboxBindings` | Present, requires G1 |
| IAM-12 | OpenSearch KMS grant | same template: `CreateOpenSearchGrantOnExactSandboxKey` | Present, requires G1 |
| IAM-13 | ENI discovery/readback | config/*plan-read-v1: `RegionalDiscovery` includes ec2:DescribeNetworkInterfaces; attached to both roles | Present |
| IAM-14 | Public ECR reader exact role allowlist | config/*apply-sandbox-iam-v1 and *plan-read-v1 | Present |
| IAM-15 | GitHub OIDC immutable subject trust | module/main.tf: `github_repository_subject`, environment and main-ref trusts; module/w12_prerequisite_images.tf | Present; actual GitHub OIDC subject configuration remains external |
| IAM-16 | Public ECR STS bearer token condition correction | module/w12_prerequisite_images.tf: `AuthorizePublicEcrServiceBearerToken`, no old service condition; token-only role and approved exception retained | Present |
| IAM-17 | Foundation IAM role lifecycle/attachments/PassRole | config/*apply-w6-eks-iam-v1; module/foundation.tf creates cluster/node/Bedrock roles and AWS-managed attachment edges | Present; bootstrap authority prerequisite G4 |
| IAM-18 | Foundation log-group write scopes | config/*apply-w6-observability-v1: `CreateAndManageExactLogGroups` | Present |
| IAM-19 | Dashboard writes | same template: `ManageExactDashboard` | Present |
| IAM-20 | SNS topic create/manage | same template: `ManageExactAlertTopic` | Present |
| IAM-21 | SNS GetSubscriptionAttributes on topic ARN | config/*plan-read-v1: `ReadExactSandboxAlertSubscriptionAttributes`; attached to both roles | Present; do not judge only the older subscription-suffix statement |
| IAM-22 | EKS KMS grant | config/*apply-w6-eks-iam-v1: `CreateEksGrantOnExactSandboxKey` | Present, requires G1 |
| IAM-23 | Plan reads of new foundation roles | config/*hcp-w6-read-recovery-v1 inline documents for both HCP roles: `W6ReadExactCreatedRoles` | Present |
| IAM-24 | Plan SNS topic reads | same inline documents: `W6ReadExactAlertTopic` | Present |
| IAM-25 | Plan dashboard reads | same inline documents: `W6ReadExactDashboard` | Present |
| IAM-26 | Node-group service-linked-role read/create | config/*apply--*eks-nodegroup-sns-recovery-v1: exact GetRole plus service-constrained CreateServiceLinkedRole | Present; service-linked role itself intentionally outside adoption |
| IAM-27 | SNS Unsubscribe on topic ARN | same inline document: `UnsubscribeExactSandboxAlertTopic` | Present |
| IAM-28 | FIS action-resource authorization | config/*apply--*fis-template-recovery-v1: `CreateOnlySandboxEksPodDeleteTemplate` includes action and template ARNs; exact PassRole | Present |
| IAM-29 | Capstone CodeBuild log lifecycle/read | config/*apply-capstone-codebuild-logs-v1; *plan-read-v1 exact log read statements | Present |
| IAM-30 | CodeBuild project lifecycle | config/*apply-capstone-codebuild-project-v1: `ManageExactCapstoneCodeBuildProject` | Present |
| IAM-31 | CodeBuild PassRole and reads | same write template: `PassExactCapstoneCodeBuildServiceRole`; *read-capstone-codebuild-project-v1 attached to both HCP roles | Present |
| IAM-32 | Bootstrap ownership and drift reconciliation | platform_iam.tf, platform_iam_imports.tf, module/*.tf; complementary sandbox removed blocks | Implemented; 66 declarations/imports covered by checks. Extra unlisted attachments are not automatically removed |
| IAM-33 | Physical binding freshness | platform_iam_variables.tf supports exact overrides; platform_iam.tf merges captured defaults | Partial: mechanism exists, freshness and staged refresh remain G1/G3 |
| IAM-34 | Complete permission-review evidence | tests/security/test_bootstrap_iam_ownership.py; historical capture comparison | Partial: structural checks and preserved documents are not complete effective-authorization proof (G6) |

## Workbook items that do not belong entirely in bootstrap IAM

All 22 related blockers were reviewed for ownership; they must not be described
as permissions fixed simply by adding Terraform statements.

- CTX-01/08/09/10/11/12: local SSO/HCP credentials, service-account/team
  binding, GitHub variables and workflow token injection. The workflow now has
  `GH_TOKEN` bindings; secret values, actual team identity and GitHub environment
  configuration are not created by these AWS bootstrap Terraform files.
- CTX-02/03/04/05: policy size, AWS CLI file arguments, PowerShell runtime and
  Analyzer-client handling. Splitting the policy is preserved, but execution
  wrappers and analyzer diagnostics remain separate tooling concerns.
- CTX-06/07: Public ECR throttling and Docker credential location belong to
  build/workflow execution; the reader role does not by itself fix these.
- CTX-13/14/21: Helm target, namespace/RBAC ordering and temporary EKS access
  belong to the Kubernetes and sandbox stages. Retaining the IAM role is not
  equivalent to granting permanent Kubernetes administration.
- CTX-15/16/17/18/19/20: tainted partial resources, existing log import,
  adoption tooling, plan metadata, scanning/OPA and ECR image purge are
  state, governance or lifecycle concerns. Historical repairs are not fresh
  execution evidence.
- CTX-22: bootstrap administrative authority is G4 above.

## Review boundary

No source fixes, policy changes or deployment were made during this cross-check.
The original workbook was left unchanged. The bootstrap migration's historical
zero-change plan and successful deployment receipts remain historical evidence;
they do not certify the current live account or a future fresh deployment.
