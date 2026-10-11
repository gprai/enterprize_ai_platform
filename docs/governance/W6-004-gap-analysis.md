# W6-004 gap analysis

## Purpose

This document identifies what remains incomplete, partially proven, waived or
outside the W6-004 evidence boundary. It distinguishes closure blockers from
future production-readiness work. A gap is not converted to PASS merely
because the synthetic lifecycle otherwise succeeded.

## Current position

| Area | Current classification |
|---|---|
| Stage 6 integrated validation | **PASS** |
| Stage 7 bounded resilience | **PASS** |
| Application rollback | **PASS_WITH_TELEMETRY_GAP** |
| Infrastructure rollback | **PASS_WITH_TELEMETRY_GAP** |
| Project-owned resource teardown | **PASS** |
| Overall W6-004 closure | **INDETERMINATE_PENDING_KMS_AND_BILLING_LAG** |
| Production readiness | **NOT ESTABLISHED** |
| Final owner approval | **PENDING COLUMN N** |

## Priority model

| Priority | Meaning |
|---|---|
| P0 | Required before W6-004 lifecycle closure. |
| P1 | Required before a production-readiness claim. |
| P2 | Operational/tooling improvement that reduces future error and effort. |

## Closure-blocking gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-01 | Cost Explorer was USD 0 immediately after teardown, but delayed billing was not yet mature. | Late charges could invalidate the lifecycle ceiling assessment. | Complete the scheduled 24-, 48- and 72-hour read-only cost checks; compare cumulative lifecycle cost with the USD 20 ceiling; preserve raw and normalized results. | All checkpoints completed, no unexplained project charge, final cost within the ceiling or a new explicit owner decision. | P0 | Owner; **INDETERMINATE**. |
| GAP-02 | Platform KMS key `41b46eac-902c-4d53-bb09-2f4a183fa268` remains `PendingDeletion` until approximately `2026-10-17T00:34:51.498000+08:00`. | The resource still exists until AWS completes scheduled deletion. | After the deletion date, query KMS by exact key ID and verify physical absence; reconcile tags and cost if still present. | Native KMS `NotFoundException` or equivalent exact absence evidence after the scheduled date. | P0 | Owner; **OPEN_FOLLOW_UP**. |
| GAP-03 | Bootstrap KMS key `d869548f-8792-441a-a77a-3028d693e7cd` remains `PendingDeletion` until approximately `2026-10-17T00:57:48.306000+08:00`. | Same residual-resource risk as GAP-02. | Perform the exact post-deletion KMS absence check and preserve evidence. | Native exact-key absence after the scheduled date. | P0 | Owner; **OPEN_FOLLOW_UP**. |
| GAP-04 | Column N final reviewer, role, decision and timestamp are not recorded. | Documentation could be mistaken for final owner closure. | Reconcile GAP-01 through GAP-03, then close all W6 documents together under one owner decision. | Consistent Column N status across evidence, sign-off, rollback, cleanliness and tracker records. | P0 | Owner; **PENDING**. |

## Validation and quality gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-05 | The W3 39-case deterministic golden set was not run against the live Nova 2 Lite deployment. W6-004 preserved only one grounded synthetic prompt and one abstention prompt. | Two examples cannot establish broad answer quality, retrieval recall, grounding or regression resistance. | Build a synthetic, privacy-safe live golden set; define deterministic scoring tolerances, citation and abstention rules, token/cost bounds, and rerun against the immutable candidate. | Versioned dataset, runner, raw responses, scoring report and owner-approved thresholds. Status remains **NOT RUN** until then. | P1 | Application/quality owner; **NOT RUN**. |
| GAP-06 | Synthetic authentication and wrong-tenant denial passed, but production identity federation, user lifecycle and real tenant provisioning were not tested. | Sandbox tokens and tenants do not prove production authentication, authorization or offboarding behavior. | Test the approved production identity provider, claim mapping, key rotation, tenant provisioning/deprovisioning, break-glass access and audit trail in a non-production production-like environment. | Identity test matrix with positive, negative, rotation and deprovisioning evidence. | P1 | Security/identity owner; **NOT ESTABLISHED**. |
| GAP-07 | Initial SLO targets were validated as architecture and exercised in a short synthetic lifecycle, not over a production-size population or 30-day window. | Availability, latency and quality targets could be unattainable or misleading under real traffic. | Run a production-like soak with defined traffic, minimum population, error-budget calculations and alert validation. | Complete SLI population, objective results, burn-rate behavior and owner decision. | P1 | SRE/service owner; **NOT ESTABLISHED**. |
| GAP-08 | Stage 7 deleted exactly one application pod. Node loss, Availability Zone impairment, dependency degradation and sustained load were not exercised. | The platform may recover from pod loss but fail under broader infrastructure or dependency faults. | Design separately approved bounded exercises for node drain/loss, AZ-aware scheduling, OpenSearch degradation, Bedrock throttling, telemetry outage and controlled load. | Per-scenario stop conditions, execution records, recovery objectives and no unresolved safety findings. | P1 | Resilience owner; **NOT RUN**. |
| GAP-09 | Infrastructure rollback changed only node-group `min_size` from 2 to 1 while desired capacity stayed 2; no node was terminated. | It proved saved-plan regression/restoration, not full infrastructure replacement or disaster recovery. | Test restore from a materially distinct but safe configuration, and separately test state/backend recovery and cluster recreation in an isolated environment. | Exact known-good identities restored, native configuration equal, workloads healthy, and recovery-time/recovery-point evidence. | P1 | Infrastructure owner; **PARTIAL SCOPE**. |

## Telemetry and audit gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-10 | Application rollback metrics had no datapoints in the queried window; availability-burn and safety alarms remained `INSUFFICIENT_DATA`. | Functional rollback could pass while alerting is blind. | Emit stable metrics before the exercise, validate exact dimensions and periods, require alarms to be `OK`, run rollback, and verify expected datapoints and state transitions. | Metric datapoints cover the rollback window and both alarms are demonstrably evaluable. | P1 | SRE owner; **PARTIAL**. |
| GAP-11 | Infrastructure rollback could not correlate its bounded Bedrock invocation to a model-invocation log event. | Request-level auditability across application, CloudTrail/Bedrock and telemetry is incomplete. | Propagate application test ID and provider request ID; inventory the exact log destination and delivery delay; query a widened bounded window; add delivery success/failure alarms. | One-to-one correlation among test ID, application request, Bedrock request ID, model ID, token use and invocation log. | P1 | Application/SRE owner; **PARTIAL**. |
| GAP-12 | Complete prompt/response retention covered only two explicitly synthetic Stage 6 prompts, not every model interaction. | Full forensic reconstruction is unavailable, while broad payload logging would create privacy risk. | Define a scoped transcript policy: synthetic-only payload retention, redaction, encryption, access controls, retention/deletion, request-ID correlation and explicit temporary enablement. Prefer application-scoped capture over account/Region-wide logging. | Approved policy plus tests proving sensitive data exclusion, bounded retention and correlation. | P1 | Security/data owner; **LIMITED BY DESIGN**. |
| GAP-13 | CloudWatch application and alarm metric dimensions differed from script assumptions. | Future evidence queries may silently miss valid series or classify data incorrectly. | Publish a versioned metric/dimension contract and generate queries from inventory. Add contract tests at the emitter and collector. | Stable documented dimensions and successful exact-series queries in deployment/rollback tests. | P2 | SRE owner; **OPEN**. |
| GAP-14 | Backup alert ownership and production alert destinations are not established. | A live incident may not reach an accountable responder. | Define primary/backup on-call ownership, routing, escalation, acknowledgement and test-message cadence. | Confirmed destinations and an owner-observed end-to-end alert exercise. | P1 | Operations owner; **NOT ESTABLISHED**. |

## Security and supply-chain gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-15 | Final image retained 19 Trivy High findings, 24 Grype top-level High findings and 42 governed recursive High findings under an owner waiver. | Known vulnerabilities may become exploitable or exceed future risk tolerance. | Refresh base image and dependencies, map each finding to exploitability and fix version, rebuild, rescan and require a new waiver only for remaining justified findings. | Zero Critical, materially reduced High findings, no secrets, updated SBOM/provenance and explicit residual decision. | P1 | Security/application owner; **WAIVED FOR BOUNDED MVP**. |
| GAP-16 | Trivy warned that some OS packages were skipped because PURL namespaces did not match the detected Chainguard OS. | Vulnerability coverage may be incomplete. | Validate packages using Chainguard advisories/SBOM tooling and a scanner/version that recognizes the package namespace; compare results with Grype. | Documented package coverage with no unexplained skipped governed packages. | P1 | Supply-chain owner; **OPEN**. |
| GAP-17 | Bedrock invocation logging is account/Region scoped when enabled for payload capture. | Unrelated model traffic could be retained, creating privacy and governance exposure. | Keep it disabled by default; require time-bound approval, synthetic-only traffic, dedicated destination, access controls and verified disablement. | Configuration-before/after evidence and zero unrelated payloads in the bounded archive. | P1 | Security/cloud owner; **CONTROLLED LIMITATION**. |
| GAP-18 | Temporary IAM trust and inline policies were needed for private OpenSearch and exact S3-version teardown access. | Emergency access paths increase privilege and restoration risk. | Design a permanent least-privilege teardown role or pre-approved private admin job with exact resource scoping, short sessions and automatic restoration checks. | Policy tests, dry-run, positive required-access probes, negative unrelated-access probes and automatic cleanup evidence. | P2 | Cloud security owner; **OPEN**. |

## Platform and operational tooling gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-19 | Lifecycle scripts required repeated corrections for optional properties, scalar/array behavior, `[ref]`, hashing APIs, process arguments, encodings and native stderr. | Manual command execution remains error-prone and expensive. | Convert recurring commands into repository-owned modules/scripts with Pester tests on Windows PowerShell 5.1 and PowerShell 7. Test zero/one/many objects, missing properties, failure injection and timeouts. | CI passes compatibility tests; an injected command failure cannot produce PASS; scripts are versioned and documented. | P2 | Platform tooling owner; **OPEN**. |
| GAP-20 | Terraform invocation and validation logic confused argument boundaries, plan/state schemas, blocks versus instances and optional metadata. | A future plan may be rejected incorrectly or, worse, classified too broadly. | Create typed plan/state normalization, schema fixtures and one approved Terraform 1.16.1 runner. Validate source, state, plan hash, OPA result and deadline in one pre-apply contract. | Fixture suite across count/for_each/modules and successful no-mutation rehearsal. | P2 | Infrastructure tooling owner; **OPEN**. |
| GAP-21 | Backend still uses deprecated `dynamodb_table` locking. | Future Terraform versions may remove support; dual locking designs can complicate recovery. | Plan and test migration to S3 `use_lockfile`, including interrupted-operation recovery and rollback. | Fresh backend initialization, lock contention test, state recovery test and retirement decision for DynamoDB. | P2 | Infrastructure owner; **OPEN**. |
| GAP-22 | Some long-running commands did not announce maximum wait or emit periodic progress. | Owners may interrupt healthy operations, creating avoidable partial state. | Every bounded wait must print purpose, deadline, poll interval and progress; support safe rejoin/reconciliation. | Test that interrupted waits can be rejoined without duplicate mutation. | P2 | Platform tooling owner; **OPEN**. |
| GAP-23 | The original OpenSearch teardown order removed the application namespace before private index deletion, requiring temporary connectivity reconstruction. | Teardown became more complex and needed temporary access mutations. | Revise the future runbook so exact private data-plane deletion occurs while an approved connectivity path still exists, unless a dedicated teardown path is already available. | Dry-run demonstrating data-plane cleanup, access restoration and then namespace deletion in fixed order. | P2 | Platform owner; **OPEN**. |
| GAP-24 | Resource Groups Tagging API produced 15 stale post-destroy entries. | Discovery-only APIs can cause false residue and cost conclusions. | Make native service APIs mandatory for final existence and cost-bearing classification; record tagging lag separately. | Automated reconciliation shows tag entry plus native absence without classifying it as live residue. | P2 | Cloud governance owner; **OPEN**. |
| GAP-25 | Bootstrap state had to be reconstructed before teardown. | Lost or incomplete bootstrap state could strand foundational resources. | Add periodic bootstrap state health checks, encrypted external recovery snapshots and a rehearsed exact-resource recovery procedure. | Recovery rehearsal produces a zero-drift state without AWS mutation. | P1 | Infrastructure owner; **OPEN**. |

## Governance and readiness gaps

| ID | Gap and evidence | Risk | Required solution | Acceptance evidence | Priority | Owner/status |
|---|---|---|---|---|---|---|
| GAP-26 | Sandbox success does not establish production readiness. | Production data, traffic, identity, scaling, support, compliance and operational ownership differ materially. | Create a separate production-readiness review covering identity, privacy, threat model, capacity, DR, SLOs, support, cost, compliance and change management. | Approved production-readiness checklist and environment-specific evidence. | P1 | Architecture/owner; **NOT ESTABLISHED**. |
| GAP-27 | Several controls were initially split between the Stage 6 Job and owner-run exercises without a single pre-approved test matrix. | Scope ambiguity can cause an owner to believe every control was executed. | Publish a control matrix listing executor, mutation type, expected result, evidence and dependency before execution. Final PASS must require every mandatory row to be PASS. | Signed matrix with no unexplained `NO_DATA`, `NOT RUN` or missing evidence. | P2 | Validation owner; **OPEN**. |
| GAP-28 | Accepted warnings, partial telemetry and failed attempts are spread across several evidence roots and documents. | Future reviewers may select only a favorable record and miss limitations. | Maintain one immutable success index that references final and superseded records, waivers, gaps, hashes and closure tails. | Automated link/hash validation and one owner-reviewed index. | P2 | Governance owner; **PARTIALLY IMPLEMENTED**. |

## Recommended remediation sequence

### Phase 1 — close W6-004 without changing its history

1. Complete the scheduled 24-, 48- and 72-hour billing checks.
2. After 2026-10-17, verify physical absence of both exact KMS keys.
3. Repeat native residue reconciliation if either check exposes a conflict.
4. Update all governed W6 closure records together under Column N.

### Phase 2 — harden repeatability

1. Productize and test the PowerShell/AWS/kubectl/Terraform runners.
2. Version the Stage 6 control matrix and metric/dimension contracts.
3. Add reliable request-ID propagation and telemetry correlation.
4. Rehearse bootstrap state recovery and backend lockfile migration.

### Phase 3 — address production-readiness evidence

1. Remediate or re-waive High vulnerabilities using fresh scans.
2. Run a live privacy-safe golden set and production-like load/soak tests.
3. Validate production identity, alert routing and statistically meaningful
   SLOs.
4. Exercise broader resilience and disaster-recovery scenarios in a separate
   approved environment.

## Definition of gap closure

A gap may be marked closed only when:

- its required evidence exists and hashes/links validate;
- any mutation used to close it had separate current authority;
- failed and superseded attempts remain preserved;
- no `NO_DATA`, `NOT RUN`, waiver or partial result is silently converted to
  PASS; and
- the accountable owner records the decision and timestamp.

## Related records

- [W6-004 lifecycle evidence](../test-evidence/W6-004.md)
- [Week 6 sign-off](../deployment-records/W6-signoff.md)
- [W6-004 resource cleanliness](../resource-cleanliness/W6-final.json)
- [W6-004 application rollback](../rollback-records/W6-application.md)
- [W6-004 infrastructure rollback](../rollback-records/W6-infrastructure.md)
- [W6-004 issue and remediation register](W6-004-issue-and-remediation-register.md)

## Final Owner Approval

- Documentation status: **PREPARED FOR OWNER REVIEW**.
- Open P0 gaps: billing maturity, two KMS deletion checks and Column N.
- Lifecycle status: **INDETERMINATE_PENDING_KMS_AND_BILLING_LAG**.
- Production readiness: **NOT ESTABLISHED**.
- Tracker update responsibility: **Owner**.
