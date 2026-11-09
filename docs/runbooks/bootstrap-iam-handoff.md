# HCP bootstrap IAM binding handoff

For the owner-executed independent role setup and partial-apply recovery repairs,
see [deployment readiness repairs](deployment-readiness-repairs.md). The setup helper
only establishes the external execution identities; HCP performs the subsequent
Terraform plan/apply. Normal refresh permissions do not authorize bootstrap teardown.

Implementation reviewed 2026-11-01. Offline validation only; live execution is
NOT RUN. This closes the six source gaps in the IAM workbook cross-check without
claiming that a future AWS deployment is guaranteed to succeed.

## Retained prerequisites and authority

Run only reviewed, clean main from `E:\AI\enterprise_ai_platform`. Retain the
adopted bootstrap state, 17 platform roles, 66 managed IAM objects, OIDC providers
and existing GitHub/HCP setup. These refresh stages reject IAM creation, deletion
and replacement. Initial installation into an empty AWS account remains a
separate bootstrap operation; it cannot authorize its own execution identity.

The owner must bind dedicated bootstrap plan/apply AWS role ARNs through
`bootstrap_execution.plan_role_arn` and `bootstrap_execution.apply_role_arn` in
the external lifecycle inputs. HCP bootstrap workspace environment variables
`TFC_AWS_PLAN_ROLE_ARN` and `TFC_AWS_APPLY_ROLE_ARN` must match those exact ARNs.
The existing dynamic-credentials enablement must also be configured. The roles
must trust only the HCP provider, audience `aws.workload.identity`, and their
respective exact subject:

```text
organization:Enterprise_AI_AWS_Arch:project:enterprise-ai-capstone:workspace:enterprise-ai-bootstrap:run_phase:plan
organization:Enterprise_AI_AWS_Arch:project:enterprise-ai-capstone:workspace:enterprise-ai-bootstrap:run_phase:apply
```

`prepare` reports missing bindings and checks role identity/trust and the
existing-object IAM read/update permission surface. Both workspaces require the
mandatory Infracost post-plan task. Existing conflicting setup is not overwritten.
Missing setup values may be created only through the existing explicit
`--setup-missing` owner approval flow. Dedicated AWS role creation or privilege
expansion is not silently performed. These roles also need the existing bootstrap
storage/KMS and OIDC read permissions; IAM simulation is not a full workspace
authorization certification.

The local AWS session performs readback and policy simulation. HCP performs all
Terraform plan/apply and IAM writes. An HCP team token and an AWS SSO session do
not substitute for the remote execution role. The workload HCP roles are rejected
as bootstrap self-administration identities.

## Current inputs

Supply owner-approved `iam_handoff.administrator_role_arn`, `bedrock_model_id`
and `workload_expires_at`. Trust expires at the lifecycle approval deadline.
Workload expiry must cover that deadline and be no later than 24 hours after the
context's creation/approval time. The complete approved sandbox mandatory tag map
must use the same workload expiry. Each bootstrap binding stage also needs its
complete approved bootstrap `mandatory_tags` map, with that expiry, in its own
`stages.<stage>.variables`; sandbox common variables are not copied into bootstrap.
Never paste secrets into this file; reuse the existing token environment.

Physical bindings are read from exact finalized sandbox state outputs. No old
VPC, KMS, subnet, route-table or security-group ID becomes a future default.
`bindings.captured.json` is retained only as historical evidence and the first
refresh's BEFORE-side comparison when the older state lacks the new binding
output. Missing new outputs stop rather than substituting captured values.

## Owner-executed sequence

After the normal `prepare` command returns the context UUID as `$runId`, execute
these stages sequentially. Each creates an HCP non-auto-apply run, verifies its
configuration/state/plan, requires Infracost and OPA, asks exact-plan approval,
and records the final HCP state. Nothing below was executed during implementation.

```powershell
Set-Location -LiteralPath 'E:\AI\enterprise_ai_platform'
python -B -m provision.lifecycle provision --run-id $runId --stage identity-seed
python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-seed
python -B -m provision.lifecycle provision --run-id $runId --stage network-seed
python -B -m provision.lifecycle provision --run-id $runId --stage bootstrap-bind-complete
python -B -m provision.lifecycle provision --run-id $runId --stage base
```

| Stage | Exact purpose |
| --- | --- |
| identity-seed | HCP sandbox targets only VPC and sandbox KMS key; obtains new VPC/default-SG/key identities. |
| bootstrap-bind-seed | HCP bootstrap updates exact key/VPC/default-SG bindings and fresh expiries; temporarily omits only the endpoint-parent authorization statement whose subnet/route/SG IDs do not exist yet. |
| network-seed | HCP sandbox targets the default SG, private subnets, route table and endpoint SG. |
| bootstrap-bind-complete | HCP bootstrap restores the full endpoint statement using all new physical identities. |
| base | Full untargeted sandbox convergence before images, EKS and other dependent stages. |

The two fixed targeted plans are dependency preparation, not a declaration that
the full configuration is converged. Dependent service provisioning is blocked
until the complete IAM handoff. Continue the image/foundation/PKI/activation and
governed release stages in the main lifecycle runbook afterward.

The handoff records both workspace state identities and checks for concurrent
sandbox runs, bootstrap state changes and expired approvals. Bootstrap changes
must be exact tracked HCP policy/trust documents or bounded physical-ID/expiry
substitutions in workload policies, plus approved expiry tags/gate values. Added
actions, unrelated principals, unexpected resources and destructive actions stop.
The dedicated OPA policy complements this Python semantic review; it does not
replace it. Uncertain POST results are reconciled against the same journal and
must not trigger a duplicate run.

## Preservation, evidence and limits

All 19 historical HCP policy/trust documents and 16 managed-policy attachment
edges are regression-bound to the captured incident baseline. The sole approved
permission narrowing adds exact mandatory tag keys/values, Name and ExpiresAt to
initial tagging of the exact default security group. Existing KMS grants, SNS
topic-scoped reads/deletes, ENI reads, FIS action scope and CodeBuild repairs remain.
The 17-role/66-object ownership model is unchanged.

Local logs remain under `report`; canonical active/completed contexts and phase
evidence remain under the approved external evidence hierarchy. The workbook was
not overwritten while open in Excel. Its companion cross-check records the
implementation, and the original findings remain visible as historical findings.

Positive IAM simulation is only preflight evidence. Service context, SCPs,
permissions boundaries, quotas, propagation and provider behavior can still cause
failure. Missing simulation context or an uncovered resource is rejected. See
[AWS simulation API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)
and [per-resource evaluation results](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html).
No live permission proof, deployment success, release, teardown or billing closure
is inferred from these offline checks.
