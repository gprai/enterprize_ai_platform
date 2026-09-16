# W5-004 sandbox lifecycle record

## Outcome

The owner completed a synthetic, non-sensitive, non-production sandbox lifecycle: bootstrap creation, platform deployment, post-apply verification, targeted rollback, platform teardown, native orphan verification, bootstrap teardown, and final residue verification. Infrastructure execution succeeded, but production/model readiness did not result from that success.

## Deployment sequence

1. Bootstrap prerequisites and identity controls were reviewed before platform work.
2. `saved-plan-015` applied 5 creates and 25 updates. It created the OpenSearch domain and four log groups while applying lifecycle, network, IAM, storage, endpoint, KMS, and expiry updates.
3. Post-apply PA-02 through PA-15 passed. PA-16 was `WAIVED/ACCEPTED_RISK — NOT PASS`; PA-17 and PA-18 passed.
4. `saved-plan-016` then removed the OpenSearch domain and four managed log groups through a narrowly targeted rollback. The Logs resource policy was intentionally retained until full platform destroy.
5. `saved-destroy-017` removed the remaining platform resources. `saved-bootstrap-destroy-018` removed the bootstrap/state resources last.

## KMS compatibility and security outcome

The original OpenSearch log-group creation failure was traced to CloudWatch Logs compatibility with the KMS key policy. The bounded amendment removed only the `kms:ViaService` condition from `AllowExactOpenSearchLogEncryption`. It retained the regional Logs service principal, seven KMS actions, wildcard key resource, and four exact log-group encryption-context ARNs. Subsequent synthetic non-sensitive CloudWatch Logs write/readback verification passed.

Post-apply controls verified private-network topology, OpenSearch readiness/security configuration, log-group KMS bindings, KMS rotation/policy configuration, S3/ECR controls, IAM/OIDC controls, expiry tags, owner-expiry sentinel, native project inventory, and secret-exposure review. These controls established sandbox infrastructure behavior only; they did not invoke Bedrock workloads, load-test the platform, validate model quality, or establish production readiness.

## Resource and state results

The forward plan identity was `d69eaf64751b004ff37d42147e5f61ffbdd987d0a9b1982edffb2f0c16223788`; plan JSON identity was `5bba05bcd1405528299a30b9518efc0300f0313814b26082f1ad7ed6f5f9a7be`. After post-apply verification, platform state lineage was `7465ed2e-a39c-afdd-f172-5792d3ec2f85`, serial `8`.

The targeted rollback was verified at serial `9`. It proved the approved five-resource OpenSearch rollback path, not independent last-known-good rollback assurance. The lack of an independently defined pre-deployment rollback target remains a production-readiness limitation.

## Cost and readiness limitations

Cost eligibility remained `WAIVED/ACCEPTED_RISK — NOT PASS`; `USD_3_BOUNDED=false`. The advisory estimate, fixed short-window estimate, synthetic-input boundary, and owner cost-containment restrictions did not produce actual billing proof. Production eligibility remains `BLOCKED`.

The source worktree is uncommitted. An earlier full Python suite passed, but the final KMS/OPA source state lacks a recorded all-suite green rerun after a later protected-identity mismatch; the isolated retry passed only. This deployment record must not be used to claim release-ready code.

## Fields pending Column N

- Documentation closure only; no infrastructure reactivation or plan reuse.
- Keep full-suite rerun, delayed billing reconciliation, KMS-tail absence checks, source review, and Git review as owner follow-ups.

## Final Owner Approval

 - Prompt/task ID: `W5-004`.
 - Reviewer: Gyan Prakash Rai, Project Owner and Final Approval Reviewer.
 - Owner decision: **FINAL APPROVAL AFTER OWNER TEST — APPROVED** on `2026-09-16 16:37:21 SGT`.
 - Final status: the owner-approved synthetic sandbox lifecycle is documented as complete. Production readiness and model readiness remain `BLOCKED`.
 - Code and documentation review status: this documentation closure is approved; the uncommitted Column L source baseline remains subject to separate source review, complete current-suite evidence, and Git authorization.
 - Owner-executed test status: preserve the recorded PASS results and the recorded final full-suite gap.
 - Warnings, risks, gaps, and scope limitations: all approved Column M items are accepted; no additional risk is silently accepted.
 - NOT RUN and INDETERMINATE: Bedrock workload use, load/soak/performance testing, production deployment, and all other recorded NOT RUN work remain NOT RUN; no historical INDETERMINATE result becomes PASS; open INDETERMINATE activities: none.
 - Deployment, rollback, teardown, and residuals: forward sandbox deployment, targeted rollback, platform destroy, and bootstrap destroy completed as recorded. Two KMS keys remain `PendingDeletion` rather than absent.
 - Deferred actions and owner: the manifest's full-suite, billing, KMS-tail, source-review, and Git-review actions remain open for Gyan Prakash Rai unless separately reassigned.
 - Conditions: do not infer production/cloud/model readiness from synthetic sandbox execution.
 - Next-task handover: W6-12 is `NOT RUN` and must use fresh artifacts and approvals.
 - Tracker update responsibility: Owner.
