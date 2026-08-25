# W2-004 — Local retrieval rollback record

## Business purpose

This record shows that the owner exercised the approved W2-004 failure boundary and then revalidated the known-good local retrieval behavior. The objective was to demonstrate a controlled recovery decision without claiming that production code, a deployment or cloud infrastructure was rolled back.

## Scope and architecture

The exercise used the local one-shot retrieval runner and internal-only Qdrant service on the logical `qdrant_internal` network. The regression override was test-scoped and non-mutating outside the approved W2-004 collection boundary.

## Owner-executed evidence

| Activity | Result | Meaning |
| --- | --- | --- |
| Approved regression phase | **PASS with historical failure retained** | The owner executed the controlled failure/remediation sequence. Its failure evidence remains visible. |
| Known-good rollback validation | **PASS** | One selected test passed in 17.57 seconds and revalidated the approved behavior. |
| Exact W2-004 collection removal | **PASS** | One selected removal test passed in 2.50 seconds. |
| Application/source version rollback | **NOT RUN** | No code revision, commit, package or deployed release was rolled back. |
| Production/cloud rollback | **NOT RUN** | No production or cloud deployment existed in this task. |
| Backup restore or disaster recovery | **NOT RUN** | Outside W2-004 local scope. |

## Failure and recovery story

The controlled regression demonstrated that an incorrect test-scoped expectation is detected rather than accepted. The owner then ran the known-good rollback validation, which passed, and removed only the W2-004 collection. This is evidence that the bounded local workflow can return to its approved state; it is not evidence of a production release rollback.

The approved rollback model was:

1. **State N:** known-good retrieval configuration and expectations.
2. **State N+1:** bounded, test-scoped, non-mutating in-memory or environment expectation override.
3. **Detection:** the regression check identified the N+1 mismatch and retained that failure evidence.
4. **Rollback:** removal of the N+1 override returned the workflow to State N.
5. **Verification:** health, idempotent ingestion, Q1–Q4 top-five retrieval, authorization isolation and quarantine absence were revalidated. Destroying the environment was a separate teardown action, not rollback.

Other historical execution failures also remain visible in the W2-004 task evidence: an initial Docker build-context/COPY mismatch and a missing `W2_002_MODEL_BLOBS_HOST` prerequisite stopped their respective operations until bounded remediation or owner configuration was supplied.

## Risks and limitations

- The exercise did not test a production database restore, blue/green deployment, release promotion, source-control revert or cloud disaster-recovery procedure.
- No load, concurrency, availability or cross-region recovery evidence was supplied.
- Shared immutable Qdrant and Python images were retained with their approved identities and digests recorded in the W2-004 task evidence.
- Shared BuildKit cache was retained for reusable local Docker build layers. Size is **NOT RECORDED — OWNER-ACCEPTED EVIDENCE GAP** because no owner-recorded measurement is available. Residual risk is undisclosed disk use and future eviction or recreation; Gyan Prakash Rai will measure or remove it through separately approved Docker-cleanliness or disk-governance work.
- Real Presidio, final Q5 safe abstention, generated answers, citations, production deployment, live AWS/OpenSearch and cloud rollback were **NOT RUN**.

## Teardown outcome

Task-owned Qdrant and runner resources were removed. The exact task collection was removed. The external W2-002 model cache was subsequently removed. Final teardown tests and the zero-residue verifier passed.

## Final Owner Approval

- Prompt/task ID: `W2-004`
- Reviewer: Gyan Prakash Rai
- Reviewer role: Project Owner and Approval Reviewer
- Decision: **APPROVED FOR FINAL DOCUMENTATION CLOSURE — W2-004**
- Approval timestamp: 2026-08-25 17:52:46 SGT (UTC+08:00)
- BuildKit waiver timestamp: 2026-08-25 17:57:55 SGT (UTC+08:00)
- Final status: **APPROVED FOR USER TRACKER UPDATE — W2-004**
- Code and documentation review: owner-tested code and all five owner-reviewed Column M documents closed
- Owner-executed test status: controlled regression evidence preserved; known-good rollback validation and exact collection removal passed
- Accepted warnings, risks, evidence gaps and limitations: local-only rollback proof; no production restore or deployment rollback; BuildKit numeric-size waiver accepted; exact dependency and production-quality gaps preserved
- NOT RUN: real Presidio and production PII-quality validation; AWS/OpenSearch; Terraform; Kubernetes; production/cloud deployment; paid model/API use; answer and citation generation; final Q5 abstention; Week 3 cited-RAG; hashed lock creation; application/source/cloud rollback; Codex Git and Excel mutation
- INDETERMINATE: None
- Deployment, rollback, teardown and residual resources: local Compose test execution, State N recovery and task teardown passed; production deployment and rollback were **NOT RUN**; external venv, disclosed shared images and BuildKit cache remain accepted
- Deferred actions and owner: Gyan Prakash Rai owns ADR corrections before W3-001, hashed lock/supply-chain hardening, real Presidio validation, Week 3 answer/citation/abstention proof, later cloud integration and future BuildKit measurement/removal
- Conditions: documentation-only five-document closure; all historical failures and limitations remain visible
- Next-task handover: State N local retrieval behavior is approved. No production rollback, real Presidio, cited answer, safe-abstention or cloud claim may be inferred.
- Tracker update responsibility: Owner
