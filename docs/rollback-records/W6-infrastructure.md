# W6-004 infrastructure rollback record

## Result

Operation `infrastructure-rollback-001` is classified
**PASS_WITH_TELEMETRY_GAP**.

## Bounded regression and restoration

The exercise intentionally changed only:

`module.eks[0].aws_eks_node_group.application.scaling_config[0].min_size`

- Regression: `min_size` 2 to 1.
- Desired capacity remained 2.
- Maximum capacity remained 3.
- No node was terminated.
- A separately generated restore plan returned scaling to 2/2/3.
- Regression apply count: 1.
- Restore apply count: 1.

The Terraform lineage remained
`8a430482-a3ec-704c-6d2d-0f82f853bba8`; the final restored state serial was
27. The restore apply evidence SHA-256 is
`1ad0a5f0055e9b77d7d1c7402997f97a46a6966ee8fd8c80dc653bbc74d62780`.

## Post-restore verification

- EKS cluster: `ACTIVE`.
- Application node group: `ACTIVE`, scaling 2/2/3.
- Ready nodes: 2.
- CoreDNS, kube-proxy, VPC CNI and EKS Pod Identity add-ons: `ACTIVE`.
- Application: two desired, updated, ready and available replicas.
- Liveness, readiness, Pod Identity, OpenSearch and approved Bedrock model:
  **PASS**.

## Scope clarification

This was a safe configuration rollback, not a full infrastructure destruction
and recreation. Lowering minimum capacity without changing desired capacity
proved exact saved-plan regression and restoration while avoiding unnecessary
node termination.

## Telemetry limitation

Post-restore telemetry was `PARTIAL` because the bounded Bedrock request could
not be correlated to a model-invocation log event. This gap remains explicit.

Authoritative result:
`E:\AI\evidence\enterprise_ai_platform\w6-004\infrastructure-rollback-001\infrastructure-rollback-final-result.json`

SHA-256:
`309d79889aef508d45389326c600031ffce3144f57184184cd2edc2655f424da`.

## Final Owner Approval

- Reviewer, decision and timestamp: **PENDING COLUMN N**.
- Tracker update responsibility: **Owner**.
