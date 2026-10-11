# Week 6 learning review — W6-004 full lifecycle

## Business lesson

The useful outcome was not merely that an application ran on EKS. The project
proved an owner-gated path from immutable build evidence to live behavior,
independent rollback and complete resource removal. The final discipline is to
leave billing and KMS tails indeterminate until their own evidence exists.

## Architecture story

The tested path was:

```text
source and dependency identity
  -> image build, scans, SBOM and provenance
  -> immutable ECR digest
  -> bound Kubernetes release
  -> EKS Pod Identity and private AWS services
  -> OpenSearch retrieval and Nova 2 Lite generation
  -> X-Ray, CloudWatch and SNS observability
  -> Stage 6 validation
  -> Stage 7 one-pod resilience
  -> application rollback
  -> infrastructure rollback
  -> platform-first/bootstrap-last teardown
  -> native residue, KMS and billing reconciliation
```

## Decisions and trade-offs

- Immutable digests and saved Terraform plans cost more time than mutable tags
  and replanning, but they made deployment and rollback identities auditable.
- The application rollback intentionally used a distinct regression image.
- The infrastructure rollback changed only node-group minimum capacity. This
  safely proved separate regression and restore plans without forcing node
  termination; it was not a full rebuild.
- Complete prompt/response logging was enabled only for a short synthetic
  window because account/Region-level model invocation logging could capture
  unrelated calls.
- High vulnerabilities were explicitly waived for the bounded MVP lifecycle;
  zero Critical remained mandatory.
- Teardown preserved evidence first, then removed exact cloud artifacts. Broad
  deletion would have been faster but would not have been safe or auditable.

## Failure and recovery lessons

1. Passing health probes did not prove vector retrieval; adapter-level and
   end-to-end checks were both required.
2. A one-second outer retrieval budget was too small even when individual
   OpenSearch transport timeouts were bounded. Startup warm-up and realistic
   operation budgets required a new image lifecycle.
3. IAM simulation does not replace a live allow/deny check, and a denial test
   must use a real catalogued but unapproved model.
4. PowerShell strict mode exposed missing-property, scalar/array and process
   argument differences. Scripts must normalize nullable shapes and validate
   syntax before owner execution.
5. Dry-run conflicts and successful mutation are different facts.
6. Kubernetes rollout completion can briefly coexist with terminating old
   pods; reconciliation should wait before declaring residue.
7. A false PASS must be invalidated and replaced by appended evidence, never
   edited out of history.
8. Terraform resource blocks and resource instances are different counts.
9. State cleanup and bootstrap destruction must occur only after native
   platform absence is proven.
10. Tagging APIs can lag deletion; direct service APIs decide whether a resource
    still exists.

## Model and RAG learning

The approved model `global.amazon.nova-2-lite-v1:0` received a grounded
synthetic question and returned the expected marker with a citation. A second
synthetic nonexistent-fact question produced the expected abstention. Those
two full API prompt/response objects were preserved. The entire W3 39-case
golden set was not run against the live deployment, so live golden-set quality
remains **NOT RUN**.

## Security, privacy and cost learning

Pod Identity removed static AWS credentials from the workload. Runtime write,
unrelated S3/KMS and unapproved-model attempts were denied. Telemetry retained
safe operational metadata, while the special transcript window used only
synthetic content and was disabled after evidence capture.

Immediate cost was USD 0 against a USD 20 ceiling, but AWS billing can lag.
The scheduled 24/48/72-hour checks are part of the result, not paperwork after
the result. The same is true for KMS PendingDeletion.

## Interview summary

In thirty seconds: W6-004 proved a complete synthetic AWS/EKS lifecycle using
immutable supply-chain evidence, live RAG and model validation, independent
application and infrastructure rollback, bounded resilience and exact
platform-first/bootstrap-last teardown. Resource teardown passed, while final
closure remains indeterminate until billing and KMS tails settle.

In two minutes: explain the identity chain from source commit to image digest,
release package, running pods, Stage 6/7 evidence, rollback targets, saved
destroy plans and native absence checks. Emphasize that failed and partial
attempts stayed visible and that rollback was never confused with teardown.

## Final Owner Approval

- Teach-back and documentation decision: **PENDING COLUMN N**.
- Current lifecycle status:
  **INDETERMINATE_PENDING_KMS_AND_BILLING_LAG**.
- Tracker update responsibility: **Owner**.
