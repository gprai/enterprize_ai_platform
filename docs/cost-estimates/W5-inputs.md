# W5-INPUTS-001 — AWS sandbox non-secret input contract

**Status:** Final — Approved  
**Tracker step:** W5-01  
**Environment:** sandbox / non-production

## Purpose and business value

This record establishes the non-secret contract between the sandbox owner and later Terraform design. It fixes the AWS account, identity, Region, networking, ownership, tagging, privacy, cost, encryption, GitHub OIDC, and Bedrock boundaries before any infrastructure or paid activity begins.

The companion `infra/environments/sandbox/terraform.tfvars.example` file is inert. No Terraform variable declaration currently consumes it. Neither file authorizes AWS access, Terraform execution, deployment, production use, or a cost-bearing service.

## Governing authority

The governing precedence is:

1. Enterprise AI Architecture Source of Truth v1.1.
2. Final-approved ADRs and owner decision records.
3. Coaching and learning records.
4. Owner-approved tracker v1.3.5.
5. Approved feature requirements, configuration, and implementation evidence.

The Column L baseline was revalidated before creation:

| Authority or baseline | Revalidated identity |
|---|---|
| Repository | `E:\AI\enterprise_ai_platform` |
| Branch | `main` |
| Reviewed HEAD | `0bc402ecf241121bb82e27c029b1d84ca76a7ca7` |
| Source of Truth v1.1 SHA-256 | `D4CE5C6D2CBBA3704E8F7F385EDEB16573CF21E009B1BF7E87914BACE03FB04F` |
| Owner Decision Compendium SHA-256 | `D738D4D9760930BF19CB8325AA66F963B2729EF999D24D75977698209DB1D216` |
| Tracker v1.3.5 SHA-256 | `C4DFF3E2E87DBFC08782E30FF7CD9295A4B0D51EA3B613C268B765DEFF3A7153` |
| Protected W3-002 baseline SHA-256 | `4BBC8F24AF911BA09356196E9285D261549926C713110F9549929E1E4AC9086F` |

The open repaired workbook, its Office lock file, and the pre-existing `.vscode/settings.json` file are owner-controlled or excluded worktree items. They are not authority for this decision, were not modified, and do not broaden this two-file boundary.

## Week 1–4 prerequisite reconciliation

- W4-12 and W4-13 are accepted as completed through the final-approved W4 sign-off and learning review. Older tracker cells are historical and do not reopen them.
- The latest recorded W4 ordinary suite finished with 724 passed, 7 skipped, and 4 deselected, with one accepted Starlette/httpx warning. This was deterministic local evidence; live AWS, provider, production, and deployment behavior remained NOT RUN.
- W4 release rollback restored the known-good local version and passed its smoke and zero-residue checks. It did not prove cloud or infrastructure rollback.
- W1-08 and SEC-003 are accepted as implemented, owner-tested, and final-approved. The owner selected removal and absence verification of the task-specific external pre-commit cache before W5-02. That owner action is outside this edit.
- No W1 local or fake result is treated as AWS service-access, quota, privacy, residency, or cost evidence.

## Scope and exclusions

This task creates only:

- `infra/environments/sandbox/terraform.tfvars.example`
- `docs/cost-estimates/W5-inputs.md`

It does not create or modify Terraform variables, providers, modules, resources, backends, policy code, application code, tests, dependencies, ADRs, evidence, CI workflows, GitHub resources, trackers, or Git metadata. No credential field is part of the approved schema.

## AWS account and identity boundary

| Decision | Approved value |
|---|---|
| AWS account ID | `526338061652` |
| Purpose | personal learning sandbox |
| Owner | Gyan Prakash Rai |
| Environment | sandbox / non-production |
| Human access | short-lived federated access through AWS IAM Identity Center/SSO |
| Long-lived AWS access keys | prohibited |

The account ID is an approved non-secret identifier. Credentials, access keys, secret keys, session tokens, passwords, private keys, role sessions, and GitHub tokens are prohibited from both files.

## Region, processing policy, and service status

| Decision | Approved value |
|---|---|
| AWS client and primary Region | `ap-southeast-1` |
| Application fallback Region | `null` |
| Allowed data-region policy | `Global Cross-Region` |
| Cross-region Bedrock processing | allowed |
| Silent substitution | prohibited for model, provider, inference profile, application Region, and fallback Region |

`Global Cross-Region` is an owner-approved Bedrock processing-policy label. It is not a concrete AWS Region identifier and does not enumerate or approve destination Regions. Bedrock controls destination selection within its Global inference profile. Under revised D19, `aws_region`, `aws_fallback_region`, `allowed_data_regions`, and `bedrock_region` are validated independently; no membership check is made between the primary Region and the processing-policy list.

The following account-level facts remain `pending_verification`: Bedrock access, Bedrock quota, OpenSearch availability, EKS availability, KMS availability, S3 availability, DynamoDB availability, and any service introduced by later Terraform design. Endpoint reachability is also unverified. Verification owner: Gyan Prakash Rai. EKS remains deferred even if availability is later confirmed.

## Network ownership, topology, egress, and destruction

| Decision | Approved value |
|---|---|
| Ownership mode | `project_owned` |
| Existing VPC ID | `null` |
| Existing private subnet IDs | `[]` |
| VPC CIDR | `10.60.0.0/16` |
| Private subnet CIDRs | `10.60.10.0/24`, `10.60.11.0/24` |
| DNS domain | `null` |
| Public ingress | `false` |
| Public subnets | prohibited |
| NAT Gateway | `false` |
| Egress mode | `private_endpoints_only` |
| Unrestricted internet egress | prohibited |

The CIDRs remain subject to later verification for RFC1918 use, uniqueness, non-overlap, availability-zone distribution, and absence of conflict with local, corporate, VPN, or cloud networks.

Approved endpoint-service labels are S3, DynamoDB, ECR API/DKR, EKS, STS, CloudWatch Logs, KMS, Secrets Manager, and Bedrock Runtime. These are owner-approved design inputs, not implemented endpoint identifiers or evidence that private connectivity exists.

Terraform may create and destroy only resources explicitly classified as project-owned. Shared VPCs, subnets, DNS zones, EKS clusters, and other shared resources are external inputs and must never enter this project's destroy boundary. Network and escalation owner: Gyan Prakash Rai.

## Mandatory tags and expiry

| Tag | Approved value |
|---|---|
| `Project` | `enterprise-ai-platform` |
| `Environment` | `sandbox` |
| `Owner` | `Gyan-Prakash-Rai` |
| `ManagedBy` | `terraform` |
| `CostCenter` | `Personal-Learning` |
| `Feature` | `MVP-001` |
| `ExpiresAt` | `TODO_OWNER` |
| `Repository` | `enterprise-ai-platform` |

`ExpiresAt` is the only approved unresolved tfvars value. It blocks the applicable later plan/apply approval, not this content review. The owner must replace it immediately before that activity with an ISO-8601 UTC timestamp no more than 24 hours after resource creation. Any extension requires a new explicit owner decision; it must not occur silently.

`2026-12-27T23:59:59Z` is retained only as the historical decision-record review deadline and must never be reused as a resource expiry. Existing spelling and case differences in application lifecycle contracts require a separately approved reconciliation before cloud mutation.

## Privacy, classification, retention, and deletion

- Permitted data is synthetic, non-production, non-sensitive data classified `PUBLIC` or `INTERNAL`.
- `CONFIDENTIAL`, `RESTRICTED`, production data, real customer or tenant data, PII, credentials, and secrets are prohibited.
- No non-AWS model or provider fallback is approved.
- Global Cross-Region Bedrock processing is approved without enumerating destination Regions.
- Sandbox data, logs, and traces must be removed during teardown or within 24 hours.
- Redacted governance and test evidence may be retained for 90 days from evidence creation under owner control.
- Evidence excludes raw prompts, answers, retrieved content, credentials, PII, provider envelopes, and chain-of-thought.

These are policy decisions, not proof of provider-side logging, deletion, residency, or privacy behavior.

## Cost ceilings, alerts, and stop-work authority

| Control | Approved value |
|---|---:|
| Monthly sandbox ceiling | USD 60 |
| Daily budget alert | USD 3 |
| Maximum paid evaluation | USD 5 |
| Alert destination | owner-controlled verified email endpoint configured through AWS Budgets/SNS |
| Budget-alert owner | Gyan Prakash Rai — Project Owner |
| Stop-work authority | Gyan Prakash Rai — Project Owner |

Stop new paid activity when the daily threshold is reached. Stop and review when projected monthly spend may exceed the ceiling. Begin teardown where continued operation would increase a breach. Budget values must never be raised silently.

These policy limits do not prove that AWS Budgets, SNS, alerts, quotas, or billing controls exist. Later service-specific approval is required. NAT Gateway is prohibited; EKS and OpenSearch are deferred; Bedrock access and paid evaluation remain unapproved pending verification.

Potential future idle or storage cost includes EKS, OpenSearch, load balancers, VPC interface endpoints, KMS keys, ECR, S3, DynamoDB, and retained logs. Request-based cost includes Bedrock tokens, KMS requests, CloudWatch ingestion, storage, data transfer, and on-demand data services. This content edit creates no AWS cost or cloud resource. Local CPU, disk, bandwidth, electricity, and owner time are real but are not automatically represented as USD 0.

## KMS lifecycle and residual ownership

| Decision | Approved value |
|---|---|
| Key type | customer-managed symmetric KMS key |
| Alias | `alias/enterprise-ai-platform/sandbox` |
| Deletion window | 7 days |
| Follow-up owner | Gyan Prakash Rai |

Immediate KMS deletion is impossible and must not be claimed. `PendingDeletion` is the only permitted teardown residual when recorded with its scheduled deletion and follow-up owner. Verification after the deletion window is mandatory. No KMS key was created by this task.

## GitHub OIDC boundary

| Decision | Approved value |
|---|---|
| Organization/user namespace | `gprai` |
| Repository | `enterprise-ai-platform` |
| Protected environment | `sandbox` |
| OIDC role name | `enterprise-ai-platform-sandbox-github-oidc` |
| Allowed ref | `refs/heads/main` |

Future trust must be restricted to this exact namespace, repository, environment, and ref. Pull-request, tag, wildcard-repository, and all-branch trust are not approved. No GitHub personal access token, AWS access key, OIDC provider, role, workflow, or repository setting was created or accessed.

## Bedrock model and application ceilings

| Decision | Approved value or status |
|---|---|
| Candidate | Amazon Nova 2 Lite |
| Underlying model identity | `amazon.nova-2-lite-v1:0` |
| Converse runtime inference-profile ID | `global.amazon.nova-2-lite-v1:0` |
| API | Amazon Bedrock `Converse` |
| AWS client Region | `ap-southeast-1` |
| Inference mode | Global Cross-Region |
| Model lifecycle | Active |
| Bedrock access | `pending_verification` |
| AWS quota | `pending_verification` |
| Automatic fallback | None |
| Maximum RAG output | 512 tokens |

AWS's public Nova 2 Lite model card was rechecked during this bounded edit and lists the model lifecycle as Active, the underlying model ID, and the Global inference ID. This public-document check does not prove owner-account access, source-Region availability, quota, latency, quality, privacy, or cost. No concrete destination Region is reproduced or approved here. See [AWS: Nova 2 Lite](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-2-lite.html).

Existing application safety ceilings remain unchanged:

| Control | Existing ceiling |
|---|---:|
| Connect timeout | 3 seconds |
| Read timeout | 20 seconds |
| Outer provider-operation deadline | 30 seconds |
| Provider adapter application attempts | no more than 2 |
| Maximum concurrent provider calls | 4 process-wide |
| Agent concurrent runs | 1 |
| Agent provider attempts | 1 |
| Agent total-token budget | 4,096 |
| Agent queue capacity | 0 |

These are application ceilings, not AWS quota or production-capacity evidence. Live invocation remains NOT RUN.

## Exact `terraform.tfvars.example` mirror

The following 30 keys, order, types, and values match the companion file exactly. `allowed_data_regions` is a processing-policy list under revised D19; it is not an AWS Region identifier list.

```hcl
aws_account_id = "526338061652"
aws_region = "ap-southeast-1"
aws_fallback_region = null
network_ownership_mode = "project_owned"
vpc_id = null
private_subnet_ids = []
vpc_cidr = "10.60.0.0/16"
private_subnet_cidrs = ["10.60.10.0/24", "10.60.11.0/24"]
dns_domain = null
egress_mode = "private_endpoints_only"
vpc_endpoint_services = ["S3", "DynamoDB", "ECR API/DKR", "EKS", "STS", "CloudWatch Logs", "KMS", "Secrets Manager", "Bedrock Runtime"]
allow_public_ingress = false
allow_nat_gateway = false
mandatory_tags = {
  Project     = "enterprise-ai-platform"
  Environment = "sandbox"
  Owner       = "Gyan-Prakash-Rai"
  ManagedBy   = "terraform"
  CostCenter  = "Personal-Learning"
  Feature     = "MVP-001"
  ExpiresAt   = "TODO_OWNER"
  Repository  = "enterprise-ai-platform"
}
allowed_data_regions = ["Global Cross-Region"]
permitted_data_classifications = ["PUBLIC", "INTERNAL"]
monthly_budget_usd = 60
daily_budget_alert_usd = 3
max_paid_evaluation_usd = 5
kms_deletion_window_days = 7
kms_follow_up_owner = "Gyan Prakash Rai"
github_organization = "gprai"
github_repository = "enterprise-ai-platform"
github_environment = "sandbox"
github_oidc_role_name = "enterprise-ai-platform-sandbox-github-oidc"
github_allowed_ref = "refs/heads/main"
bedrock_model_id = "global.amazon.nova-2-lite-v1:0"
bedrock_region = "ap-southeast-1"
bedrock_access_status = "pending_verification"
bedrock_fallback_policy = null
```

`bedrock_fallback_policy = null` records the owner-selected None policy: there is no automatic fallback or substitution.

## Deferred inputs and work

- EKS-001: existing/new cluster, namespace, domain/certificate, workload identity, and all EKS implementation inputs.
- OBS-001: production exporter, alerting, on-call ownership, and telemetry retention.
- SLO-001: production/pre-production SLIs, objectives, exclusions, error budgets, and review cadence.
- Missing ADR-015 content.
- `infra/environments/sandbox/variables.tf`, Terraform modules, providers, backends, policies, plans, and resources.
- GitHub Actions workflow and OIDC implementation.
- AWS/GitHub access, service availability, quota, live-model, privacy, network compatibility, and cost validation.
- Terraform initialization, validation, planning, application, destruction, import, and state operations.
- Deployment, rollback, teardown, cleanup evidence, and the owner-controlled tracker update.

## Risks, assumptions, warnings, and limitations

- `Global Cross-Region` does not identify or constrain concrete destination Regions; the owner has accepted that Bedrock selects destinations within its Global inference profile.
- The VPC and subnet CIDRs have not been checked against real connected networks or availability zones.
- Endpoint-service labels are not yet mapped to provider-specific endpoint identifiers.
- Positive budgets authorize no service and prove no active cost control.
- `TODO_OWNER` is deliberately unresolved for the time-dependent resource expiry and must block later plan/apply until replaced.
- Model lifecycle can change after the public-document check; account access, quota, and service availability remain `pending_verification`.
- The existing application code has not been changed to consume or validate this contract.
- Local/fake test evidence establishes no cloud, production, performance, availability, SLO, privacy, or cost claim.

Owner review must reject missing, duplicated, contradictory, expired, secret-bearing, malformed, or unsupported values; inconsistent network ownership; public or NAT behavior not approved here; invalid budget relationships; a KMS window outside 7–30 days; broadened GitHub trust; an unsupported Bedrock status; or any difference between this record and the tfvars example. Possible secret material must not be reproduced.

## Column M reconciliation results

| Classification | Result |
|---|---|
| Column L bounded content creation | PASS |
| File-count reconciliation | PASS — exactly 2 CREATE, 0 UPDATE, 0 DELETE relative to the approved pre-Column-L baseline |
| Cross-file value reconciliation | PASS — all 30 keys, their order, and shared values match |
| Secret/credential exclusion review | PASS — no credential-like field or value found |
| Automated tests | NOT RUN — not required for this content task |
| Terraform validation/init/plan/apply/destroy | NOT RUN |
| AWS access and service verification | NOT RUN |
| Bedrock access and quota verification | NOT RUN |
| Bedrock inference | NOT RUN |
| GitHub OIDC implementation | NOT RUN |
| Deployment | NOT RUN |
| Operational rollback | NOT RUN |
| Cloud teardown | NOT RUN |
| Open FAIL | None |
| Open INDETERMINATE | None within the Column M content preflight; cloud access, quota, compatibility, and availability remain `pending_verification` or NOT RUN |
| Final owner approval | FINAL APPROVAL AFTER OWNER TEST — APPROVED |

These PASS classifications apply only to bounded content creation and reconciliation. They do not upgrade any `pending_verification` or NOT RUN cloud fact.

## Lifecycle status

| Activity | Status |
|---|---|
| Terraform initialization, validation, plan, apply, or destroy | NOT RUN |
| AWS or GitHub authentication/access | NOT RUN |
| Bedrock invocation or quota verification | NOT RUN |
| Network or cloud-resource creation | NOT RUN |
| Deployment | NOT RUN |
| Operational rollback | NOT RUN |
| Operational teardown | NOT RUN |
| Cloud resources or paid activity created by W5-INPUTS-001 | None |

If the content is rejected before commit, any removal or replacement of these files requires a new owner-approved boundary. There is no cloud rollback or teardown for this task because no cloud resource was created.

## Owner review checklist

- [x] Confirm the governing authority, baseline hashes, and Week 4 prerequisite.
- [x] Confirm the account, purpose, owner, and federated identity boundary.
- [x] Confirm the independently validated primary Region, null fallback, and Global Cross-Region policy label.
- [x] Confirm network ownership, CIDRs, private egress, endpoint labels, and destruction boundary.
- [x] Confirm canonical tags and the unresolved time-dependent `ExpiresAt` rule.
- [x] Confirm synthetic-data, classification, privacy, retention, and deletion restrictions.
- [x] Confirm cost ceilings, alert destination, owner, and stop-work authority.
- [x] Confirm KMS type, alias, deletion window, residual, and follow-up owner.
- [x] Confirm the exact GitHub namespace, repository, environment, role name, and ref.
- [x] Confirm Nova 2 Lite identities, pending access/quota status, safety ceilings, and no fallback.
- [x] Compare every shared value with the 30-key tfvars example.
- [x] Confirm that no credential, secret, cloud action, test claim, or invented approval was added.
- [x] Confirm EKS, observability, SLO, deployment, rollback, and teardown remain deferred or NOT RUN.

Owner review is complete. The owner may update the tracker for W5-INPUTS-001. This approval does not authorize W5-02 or any command.

## Final Owner Approval — W5-INPUTS-001

- **Prompt/task ID:** W5-INPUTS-001
- **Reviewer:** Gyan Prakash Rai
- **Reviewer role:** Project Owner and Final Approval Reviewer
- **Exact owner approval decision:** **FINAL APPROVAL AFTER OWNER TEST — APPROVED**
- **Approval date and time/timezone:** `2026-09-03 12:59:21 SGT`
- **Final status:** **APPROVED FOR USER TRACKER UPDATE — W5-INPUTS-001**
- **Code and configuration review status:** Approved only for the bounded, inert, non-secret 30-key example contract. No executable Terraform variable, provider, backend, module, resource, policy, application, schema, or test implementation is approved or claimed.
- **Documentation review status:** Approved. This record and `infra/environments/sandbox/terraform.tfvars.example` are closed together as the complete two-document Column M manifest; no partial closure occurred.
- **Owner-executed test status:** **NOT RUN — not required for this content-only task.** The owner-supplied decision label is preserved exactly and does not convert automated testing, integration, account access, or cloud execution to PASS.
- **Column L and Column M results:** Bounded creation, file-count reconciliation, cross-file value reconciliation, and secret/credential exclusion review are PASS. Open FAIL results: None.
- **Accepted warnings, risks, evidence gaps, and scope limitations:** All items recorded in the approved W5-INPUTS-001 Column M manifest are accepted; no additional item is silently accepted. This includes Global Cross-Region processing without a Singapore-only guarantee or fixed destination Region; synthetic, non-production, non-sensitive data only; prohibited PII, credentials, restricted data, production data, and real tenant content; unverified model access, account quota, network compatibility, endpoints, budgets, and notifications; unresolved `ExpiresAt`; and no production, reliability, security, cost, or deployment-readiness claim.
- **NOT RUN and INDETERMINATE activities:** All NOT RUN activities remain NOT RUN and none is converted to PASS. This includes automated tests, Terraform validation/init/plan/apply/destroy, AWS and GitHub access, service and quota verification, Bedrock inference, OIDC implementation, network activity, deployment, operational rollback, and cloud teardown. Every historical INDETERMINATE result is preserved. Remaining open INDETERMINATE activities: None. Account access, quota, compatibility, and service availability remain `pending_verification` rather than PASS.
- **Global Cross-Region acceptance:** Accepted exactly as the owner-approved Bedrock processing-policy label. Concrete destination Regions are neither inferred nor approved, and silent model, provider, inference-profile, application-Region, or fallback-Region substitution remains prohibited.
- **`ExpiresAt` condition and owner:** `TODO_OWNER` remains unresolved. Gyan Prakash Rai owns its later replacement immediately before the applicable plan/apply review with an ISO-8601 UTC value no more than 24 hours after resource creation. This final approval does not supply or approve a resource expiry.
- **Deployment facts:** Local service startup, local deployment, production deployment, and cloud deployment were NOT RUN. No service, container, model, network, or cloud resource was created.
- **Rollback facts:** Runtime, operational, deployment, infrastructure, and cloud rollback were NOT RUN. Before commit, future removal of the two CREATE files requires owner approval. After commit, reversal is owner-controlled Git work under separate authorization. Historical W4 rollback evidence is not W5-INPUTS-001 rollback evidence.
- **Teardown and cleanup facts:** Runtime, service, container, network, and cloud teardown were NOT RUN because no such resource was created. No W5-INPUTS-001 runtime or cloud residue exists.
- **Residual-resource facts:** Repository residuals are the two approved CREATE files only. The pre-existing repaired workbook, Office lock, and `.vscode/settings.json` remained owner-controlled and unchanged. Provider/cloud cost incurred by this content task: None.
- **Deferred actions and owners:** Every deferred action in the W5-INPUTS-001 manifest remains open. Responsible owner: Gyan Prakash Rai unless another owner is explicitly recorded. This includes W5-02 Terraform design, GitHub OIDC implementation, EKS-001, OBS-001, SLO-001, ADR-015, AWS/GitHub access, service availability, quota, privacy, network and cost validation, Terraform execution, deployment, rollback, teardown, and cleanup evidence.
- **Conditions attached to approval:** Preserve all PASS, FAIL, NOT RUN, INDETERMINATE, warning, risk, limitation, deferred-work, and residual-resource facts; close every W5-INPUTS-001 Column M manifest document together; only the owner updates Excel and performs Git mutation; do not infer production or cloud readiness from local, fake, mocked, injected, or documentation-only evidence.
- **Next-task handover:** The owner may update the W5-01 tracker row. W5-02 is not authorized by this approval and requires its own governed prompt and gates. The external pre-commit cache must be removed and verified absent before W5-02, and `ExpiresAt` must be supplied before the applicable plan/apply gate.
- **Tracker update responsibility:** Owner
