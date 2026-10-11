# W7-001-remediation learning guide

## Identity and learning boundary

This guide explains `W7-001-remediation` in repository `E:\AI\enterprise_ai_platform`, remote `https://github.com/gprai/enterprize_ai_platform.git`, at HEAD `dde3e89abbc76322558ad5a38065c3d1a943bae3` and tree `70a4bfb75cb3c3f751c411b3497b42ccfc7e994d` on branch `main`. The original implementation boundary was `12 CREATE / 32 UPDATE / 0 DELETE`, followed by separately owner-approved TEST-001 remediation. Local TEST-001 passed; cloud deployment, production readiness, and W6 closure did not.

## Why this remediation was necessary

A deployment or teardown passing once proves that one particular sequence completed under one set of conditions. It does not prove that the procedure is repeatable, that a slightly different output shape will be handled safely, that a timeout cannot produce a false PASS, or that another operator can recover after an interruption.

W6 exposed weaknesses across several layers:

- Dependency warm-up and outer time budgets could disagree.
- Identity and authorization evidence was sandbox-specific.
- Telemetry queries could return no data while functional work succeeded.
- PowerShell, AWS CLI, Docker, kubectl, and Terraform had version- and shape-sensitive behavior.
- State, plan, resource block, resource instance, and digest identities could be confused.
- Teardown ordering could remove the access path needed to delete private data.
- A completed command could be mistaken for a successful outcome even when no required mutation occurred.
- Failed, superseded, partial, waived, and successful evidence was distributed across records.

Correcting a single failed attempt fixes that attempt. A durable prevention control instead defines the accepted input, rejects ambiguous or unsafe input, records immutable identity, preserves partial failure, and has regression tests that reproduce both success and failure paths.

Historical failures must remain visible because they explain why each control exists. Rewriting an earlier failure as PASS would hide the causal evidence and make it easier to reintroduce the same weakness.

## Layman explanation

Think of the platform as a large building. W6 proved that the building could be occupied, exercised, rolled back in bounded ways, and dismantled. It also revealed that some inspections depended on improvised tools, some emergency procedures were hard to repeat, some identity checks were temporary, and some evidence was spread across different folders.

W7 remediation standardizes the inspection tools, identity checks, emergency procedures, work orders, and evidence logs. A tool now records exactly what it ran. A failed inspection cannot print “passed.” Emergency access has a defined scope and expiry. Demolition is ordered so that private rooms are emptied before their access corridors are removed.

The deferred billing and KMS checks are like final utility bills and hazardous-material disposal certificates. The building work may be finished locally, but closure cannot be signed until those delayed external records arrive and the owner makes the final decision.

## Architecture impact

### API identity boundary

The new production identity module accepts claims only after signature validation has occurred elsewhere, then checks them against trusted configuration. Caller-provided headers do not create trusted identity. The output is the existing `AuthContext`, which keeps authorization before retrieval, model, or tool execution. No Cognito, Entra ID, or other provider was activated.

### Retrieval and model authorization

Existing retrieval and Bedrock boundaries remain in place. The remediation adds contracts and regression coverage for exact profiles, valid-but-unapproved denial fixtures, dependency readiness, bounded timeouts, and failure classification. Live provider calls remain separately controlled.

### Process execution

Shared command execution moved behind one provider-neutral boundary. Arguments are an immutable sequence, shell execution is not used, the working directory and environment are validated, output must be UTF-8, and timeout/cancellation cannot be reclassified as PASS.

### Terraform lifecycle

Terraform-specific rules remain separate from the generic process runner. State, plan JSON, saved binary plan, lineage, serial, blocks, instances, addresses, nested changes, unknown values, and sensitive values have distinct meanings. Future backend material uses S3 native lockfiles, but no backend was initialized or migrated.

### Kubernetes lifecycle

Pod states, object identity, deletion acknowledgement, progress, timeout, expected NotFound, partial teardown, and rejoin are typed. Private OpenSearch cleanup must happen before the namespace or network path needed to reach it is removed.

### Supply-chain security

OCI index, manifest, configuration, and archive digests are distinct. SBOM and scanner evidence is identity-bound. PURL normalization requires a reason, skipped packages remain visible, scanner disagreement remains indeterminate, waivers expire, and zero Critical remains mandatory.

### Telemetry and SLOs

Metric namespaces, dimensions, units, ownership, and readiness are versioned. Missing samples remain `NO_DATA`; they cannot silently become PASS. Alert destinations are stable external references, not personal contact details in source.

### Temporary IAM and Bedrock logging

Temporary IAM requires exact principal, actions, resources, conditions, approval, expiry, before/after identity, and restoration evidence. Bedrock logging is default-off, synthetic-only when authorized, time bounded, and requires disablement evidence. Neither control was exercised against AWS in this task.

### Recovery snapshots

The snapshot contract requires encryption identity, state lineage and serial, content hash, recovery principal, retention, cleanup owner, and no-mutation rehearsal. No real snapshot or recovery drill was created.

### Evidence and governance

Canonical serialization makes evidence hashing deterministic. Evidence lifecycle states distinguish current, failed, partial, superseded, waived, limited, closure-tail, consumed, and expired records. Production readiness is a separate review with a null decision until the owner acts.

## Major technical controls

The excerpts below are intentionally short and illustrative.

### Argv-only process execution

```python
def capture_process(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> ProcessResult:
    """Execute an already-authorized argv without a shell or ambient environment."""
```

The caller supplies already-authorized argument tokens. This avoids shell parsing, accidental expansion, and command-string ambiguity.

### Deadline and cancellation

The same boundary receives a positive timeout, optional progress callback, and cancellation token. Timeout and cancellation are explicit outcome classifications, not generic success or an unstructured exception.

### Fail-closed status classification

The runner validates executable identity, return code, output encoding, and deadline. A nonzero exit, uncertain output, timeout, or cancellation cannot enter the PASS path. This directly prevents the historical “failed command followed by PASS” pattern.

### Validated OIDC/JWT claims

```python
def validate_trusted_claims(
    claims: object,
    *,
    trusted_issuer: str,
    trusted_audience: str,
    now: datetime,
) -> AuthContext:
    value = ProductionIdentityClaims.model_validate(claims, strict=True)
```

The trusted issuer and audience come from configuration, not from the caller. Time, session, tenant, role, and group checks occur before an authorization context is returned.

### Canonical evidence serialization and hashing

```python
def canonical_json_bytes(value: object) -> bytes:
    rendered = json.dumps(
        canonical_value(value), separators=(",", ":"), sort_keys=True, allow_nan=False
    )
    return (rendered + "\n").encode("utf-8")
```

Equivalent evidence values produce the same UTF-8 bytes. Unsupported types and non-finite numbers are rejected before hashing.

### Evidence supersession and expiry

```python
def record_evidence_state(...):
    """Append one evidence lifecycle state; never replace or silently reopen it."""
```

Append-only state preserves the failed or superseded artifact while adding the later result. Consumed or expired authority cannot be reused merely because its file still exists.

### OCI digest-type separation

`OciIdentity` stores the registry index, platform manifest, image configuration, and archive/layout identities separately. Validation rejects malformed hashes and incompatible evidence shapes instead of comparing generic “image digest” strings.

### PURL and scanner reconciliation

```python
if value.original_purl != value.normalized_purl and not value.normalization_reason:
    raise ContractError("PURL normalization requires a recorded reason")
```

Normalization is an explainable representation change, not permission to suppress a finding. SBOM, Trivy, and Grype identities are required, and skipped coverage remains visible.

### Kubernetes teardown ordering

```python
if not observations or tuple(item.phase for item in observations) != TEARDOWN_ORDER:
    raise KubernetesLifecycleError("teardown phases are incomplete or out of order")
```

The control also rejects targets that existed when the expected mutation count is zero. Completing a command without deleting the intended object is not success.

### Terraform future lockfile configuration

```hcl
use_lockfile = true
```

This is a future backend contract. It does not prove that the live backend was initialized, migrated, contended, recovered, or that the historical DynamoDB lock table was retired.

### `NO_DATA` preservation

```python
missing = self.pre_exercise_samples == 0 or self.rollback_window_samples == 0
if missing and self.status is not EvidenceStatus.NO_DATA:
    raise ValueError("missing metric samples must remain NO_DATA")
```

No data means that the measurement cannot support a conclusion. It is different from both PASS and FAIL.

### Production-readiness null decision

The readiness validator uses a closed schema containing `reviewer`, `decision`, and `decided_at`. The template names the future reviewer but keeps decision and timestamp null. A reviewer name alone is not approval.

## Historical issue families

### Application and model

Cold dependency work, missing permissions, incorrect denial fixtures, signer/transport mismatch, endpoint-shape assumptions, split validation, and long unobservable calls caused failures. Existing application paths were preserved while readiness, identity, exact authorization, deadlines, and regression coverage were strengthened. Tests prove the local contracts and failure paths; live Bedrock, production IdP, and production-shaped latency remain unproven.

### Image and supply chain

Windows OCI input forms, digest-type confusion, ECR helper protocol bytes, retained High findings, skipped PURLs, and inconsistent preservation evidence complicated image assurance. Typed identities, waiver expiry, PURL reasoning, scanner reconciliation, and cardinality normalization were added. Local tests pass, but no new image was built, pulled, pushed, scanned, or assigned fresh provenance.

### Kubernetes

Terminating pods, field ownership, optional properties, expected NotFound, silent HPA waits, unsupported delete flags, residual pods, and fragile inline JSON caused repeated corrections. Typed observations, progress, exact identity, patch hashes, and teardown ordering now fail closed. No live cluster mutation or teardown was performed.

### Terraform

Scalar/array normalization, malformed argument boundaries, wrong tool versions, plan/state conflation, count semantics, nested resource changes, state loss, lineage placement, and deprecated locking all appeared during W6. The remediation adds typed boundaries, exact identities, fixtures, OPA tests, and future lockfile generation. It does not perform initialization, plan, migration, apply, rollback, or destroy.

### PowerShell and operational tooling

Fragmented conditionals, null methods, undeclared references, unavailable APIs, scalar collection behavior, URI/quoting problems, metric-search assumptions, encoding, false PASS, and accidental import roots made commands fragile. Centralized process and serialization boundaries plus compatibility tests reduce that risk. They do not authorize or replace owner control of real operations.

### Teardown and residue

False deletion PASS, lost private access, missing version-read permission, helper collisions, partial deadlines, stale tag records, pending KMS deletion, and delayed billing made closure difficult. The new contracts require acknowledgement, nonzero mutation where targets exist, exact identity, native absence, progress, checkpointing, and honest residual states. Live teardown was not rerun, and KMS/billing tails remain open.

### Governance

Split controls, repeated corrected commands, reusable failed artifacts, and provider-wide logging scope made evidence easy to misread. Complete matrices, immutable identities, append-only evidence states, expiry, and synthetic-only logging contracts make authority clearer. Final decisions still belong to the owner.

## Security learning

- **Trusted identity versus caller input:** a caller may present a token, but trusted identity comes only from validated claims and trusted configuration.
- **Authorization order:** tenant and role authorization must happen before retrieval, model, or tool calls so unauthorized work cannot leak through side effects.
- **Least privilege:** temporary IAM is an expiring, identity-bound operation contract, not an informal policy pasted for convenience.
- **Secret-free execution:** argv-only execution, environment allowlisting, and redacted evidence reduce credential disclosure through shells and logs.
- **Prompt/log privacy:** synthetic-only capture is preferred; raw protected production prompts are not acceptable evidence by default.
- **Scanner disagreement:** different scanners may legitimately disagree, but disagreement must remain visible and cannot be averaged into PASS.
- **SBOM limitations:** an SBOM identifies components; it does not guarantee that every scanner correctly matched every package namespace.
- **Waiver expiry:** a waiver is temporary authority with scope and expiry, not a permanent deletion of a finding.
- **Tamper detection:** canonical bytes and SHA-256 bind evidence to its exact source, tool, configuration, and artifact identity.
- **Native verification:** discovery/tagging systems can be stale, so final resource truth must come from the native service API.
- **Fail closed:** malformed, incomplete, stale, substituted, unknown, or unauthorized evidence produces a non-PASS classification.

## Reliability and SRE learning

An SLI is the measured indicator, such as availability or latency. An SLO is the target applied to that indicator. A configured SLO without enough SLI samples is not achieved; it is `NO_DATA` or otherwise indeterminate.

Every wait needs a deadline, polling interval, progress, last observation, cancellation, and timeout result. Cancellation does not erase partial evidence. Rejoin resumes from an identity-bound checkpoint rather than blindly repeating mutation.

Rollback restores a known-good application or infrastructure version. Disaster recovery reconstructs service after a broader loss, potentially involving state, backend, cluster, data, and images. Passing a bounded rollback does not prove disaster recovery.

Teardown ordering matters because deleting a network, namespace, or trust path can remove the only route to private data. Residual resources must be classified using native truth. Expected residuals such as KMS PendingDeletion remain open until actual absence is verified.

Production readiness combines security, identity, privacy, scale, SLO evidence, resilience, DR, support, cost, compliance, change, and residual risk. A clean local suite is necessary evidence, but it is not sufficient evidence.

## Test results and interpretation

Local TEST-001 produced:

- **2,276 passed** — the selected local repository behavior matched its assertions.
- **8 skipped** — owner-controlled real integrations were intentionally not executed; they are not PASS.
- **4 deselected** — AWS/paid tests were excluded by repository configuration; they are `NOT RUN`.
- **One warning** — an existing Starlette/AnyIO deprecation warning occurred without a test failure.
- **180/180 Terraform OPA tests passed** — the policy fixtures and current policy package behaved as specified.
- **11/11 Kubernetes OPA tests passed** — the Kubernetes policy fixtures and current policy package behaved as specified.

Ruff, MyPy, validators, secret scanning, and pre-commit also passed. These results establish local consistency, deterministic contract behavior, regression coverage, policy behavior, and task-created residue cleanup. They do not establish live AWS permissions, provider behavior, performance at scale, alert delivery, production identity integration, image vulnerability posture after a rebuild, recovery execution, or production readiness.

## Remaining work

`OWNER-DEFERRED — GAP-01 THROUGH GAP-04 — REMAIN W6 CLOSURE BLOCKERS — NO PASS OR CLOSURE INFERENCE.`

- GAP-01 requires delayed 24/48/72-hour cost reconciliation against the lifecycle ceiling.
- GAP-02 requires the platform KMS physical-absence check after scheduled deletion.
- GAP-03 requires the bootstrap KMS physical-absence check after scheduled deletion.
- GAP-04 requires the final Column N reviewer, role, decision, and timestamp.

Significant `NOT RUN` work includes live Bedrock evaluation, AWS/paid tests, real Qdrant/model integration, image rebuild and fresh scanning, new SBOM/provenance, production load/soak/capacity proof, production IdP activation, alert delivery, Bedrock logging enable/disable, recovery snapshot creation and recovery drill, deployment, application rollback, infrastructure rollback, disaster recovery, live teardown, Terraform initialization, and backend migration.

The evidence authorizes no completion, production-readiness, cloud-validation, deployment, or vulnerability-free conclusion.

## Owner teach-back questions

1. Why can a failed command never be followed by PASS?
2. What is the difference between a Terraform plan, state, and saved binary plan?
3. Why are OCI index, manifest, and configuration digests different?
4. Why does `NO_DATA` not mean success?
5. Why must OpenSearch data deletion occur before removing private access?
6. Why is a provider-neutral identity contract not a production IdP integration?
7. Why does a clean local suite not prove cloud resilience?
8. Why must KMS and delayed billing tails remain open?
9. Why do skipped packages weaken a vulnerability-free claim?
10. What is the difference between rollback and disaster recovery?

## Current governance position

- Column L implementation: `COMPLETE`
- Local TEST-001: `PASS`
- Documentation: `FINAL OWNER APPROVAL RECORDED`
- Final closure: `FINAL APPROVAL AFTER OWNER TEST — APPROVED`
- W6 closure: `INDETERMINATE_PENDING_KMS_AND_BILLING_LAG`
- Production readiness: `NOT ESTABLISHED`
- Later Week 7 feature authorization: `NOT GRANTED BY THIS DOCUMENT`

## Final Owner Approval

| Field | Owner-approved value |
|---|---|
| Prompt/task ID | `W7-001-remediation` |
| Reviewer | Gyan Prakash Rai |
| Reviewer role | Project Owner and Final Approval Reviewer |
| Decision | `FINAL APPROVAL AFTER OWNER TEST — APPROVED` |
| Decision date/time | `2026-10-10 18:24:00 SGT` |
| Learning-document status | `APPROVED; WEEKLY TEACH-BACK REMAINS OWNER-LED` |
| Code and evidence review | Original Column L implementation, TEST-001 remediation and local evidence reviewed |
| Owner-executed test status | Local TEST-001 `PASS`; 8 skipped, 4 deselected/NOT RUN and one warning retained |
| Tracker update responsibility | Owner |

The approved implementation identity is HEAD
`dde3e89abbc76322558ad5a38065c3d1a943bae3`, tree
`70a4bfb75cb3c3f751c411b3497b42ccfc7e994d`. The owner-reviewed
pre-Column-N learning-document identity is
`fba6ac6e985a2d22f70f6378711d08a66323baec1130e91d6eb03b948bb08edd`;
the evidence candidate is `docs/test-evidence/W7-001-remediation.md` with
pre-Column-N SHA-256
`e0c4f22d0f7aae677f389bf1f56d8b8210b9a1753f16176fb214aaf3d42ccb9b`.

The owner accepts exactly the warnings, risks, waivers, gaps and limitations in
the approved manifest. All `NOT RUN` and historical `INDETERMINATE` facts remain
unchanged. There are no additional owner-declared open INDETERMINATE activities
beyond the retained W6 closure tails. W6 remains
`INDETERMINATE_PENDING_KMS_AND_BILLING_LAG`; production readiness and cloud
deployment eligibility remain `NOT ESTABLISHED`.

No W7 cloud deployment, live rollback, disaster recovery, live teardown,
Terraform operation, image rebuild, registry activity, production IdP
activation, alert-delivery exercise or Bedrock logging exercise occurred.
Historical W6 rollback/teardown facts remain separate. Task-created local test
caches were removed; protected Terraform state remains retained and unchanged;
cost and KMS absence checks remain deferred.

GAP-01 through GAP-04 remain open under owner Gyan Prakash Rai unless another
owner is explicitly recorded. Approval requires preservation of every result
classification and owner-only Excel/Git mutation. The next handover is owner
tracker reconciliation; no later capability or cloud action is authorized.

The learning material and teach-back questions are approved for use. Completion
of the weekly owner teach-back was not supplied and is not inferred.
