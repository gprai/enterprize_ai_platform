# W6-004 conditional lifecycle runbook

## Purpose

This runbook captures the proven order and safety gates for a future synthetic
AWS/EKS lifecycle. It is guidance, not standing execution authority. No prior
plan, approval, token, kubeconfig, state identity, image tag or deadline may be
reused.

## Fresh preconditions for every lifecycle

Before mutation, obtain current and separately reviewed evidence for:

1. AWS account, Region, caller and permission boundary.
2. Repository branch, source commit, dependency locks and dirty-path scope.
3. Terraform 1.16.1 compatibility, backend, provider lock, state lineage and
   serial.
4. Native resource discovery, shared/service-linked exclusions and KMS tails.
5. Saved bootstrap and platform plans with exact hashes.
6. Normalized plan, OPA result and complete cost review.
7. Owner-approved cost ceiling, expiry and mutation authority.
8. Image source composition, immutable base manifests and build digest.
9. Trivy and Grype reports with current databases.
10. Explicit waivers for accepted High findings; zero Critical gate.
11. SPDX/CycloneDX SBOMs, provenance and embedding verification.
12. Registry-returned immutable digest and release-package binding.
13. Client and server-side Kubernetes admission checks.
14. Independent application and infrastructure known-good targets.
15. Fresh teardown plans and native residue verification.

Any mismatch, expiry, partial operation or indeterminate discovery freezes the
affected mutation. Never automatically retry a cloud mutation.

## Ordered deployment flow

1. Create or reconcile bootstrap/state using a saved plan.
2. Verify versioning, encryption, locking and recovery boundaries.
3. Create or reconcile network and least-privilege security controls.
4. Create data services, private OpenSearch and encrypted telemetry resources.
5. Build, scan and publish exact immutable application and collector images.
6. Create or reconcile EKS, nodes, add-ons and Pod Identity.
7. Generate a new immutable release package from the registry digests.
8. Run admission, deploy once and verify exact running digests.
9. Run health, authentication, retrieval, Bedrock, security-denial and
   telemetry checks.
10. Exercise bounded HPA/PDB and owner-approved resilience behavior.

## Rollback flow

Application rollback and infrastructure rollback are separate operations:

- Application rollback deploys an approved regression digest, verifies it is
  running, restores the exact known-good digest and rechecks behavior.
- Infrastructure rollback uses a separately saved, reviewed and approved
  restore plan. A targeted destroy is not an infrastructure rollback.

Freeze further mutation if identity, behavior, telemetry or restored native
infrastructure is failed or indeterminate.

## Complete teardown flow

The fixed order is:

1. Kubernetes workloads, Jobs and project namespace.
2. Exact synthetic OpenSearch indexes.
3. Exact synthetic/versioned S3 objects after required archive.
4. Exact project ECR digests after evidence preservation.
5. Platform Terraform resources using a reviewed destroy plan.
6. Exact versioned state objects and checksum/lock entries after platform
   absence is proven.
7. Bootstrap Terraform resources last.

At each stage, verify absence before continuing. Append partial-destroy
evidence and freeze if any stage is incomplete. Never broadly empty a bucket,
repository or account, and never delete a shared or service-linked resource.

## Closure flow

Closure requires:

- Zero unexpected AWS resources.
- Zero active cost-bearing project resources.
- Zero Kubernetes workload residue.
- Zero project ECR images.
- Zero synthetic S3 objects and OpenSearch indexes.
- Exact state and lock cleanup.
- KMS follow-up after each deletion date.
- Billing reconciliation at 24, 48 and 72 hours.
- Final lifecycle cost within the current owner-approved ceiling.

PendingDeletion and delayed billing remain `INDETERMINATE`; they are never
silently promoted to PASS.

## Evidence and privacy

Preserve immutable scans, SBOMs, provenance, release bindings, plans, policy
results, deployment records, rollback records, traces, metrics, safe logs,
CloudTrail, teardown records and hashes outside resources being destroyed.
Exclude credentials, kubeconfig contents, secret values and real tenant data.

## Final Owner Approval

- This runbook requires a new approval for every future operation.
- Current reviewer decision: **PENDING COLUMN N**.
- Tracker update responsibility: **Owner**.
