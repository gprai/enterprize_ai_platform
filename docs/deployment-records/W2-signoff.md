# Week 2 — Local Retrieval Sign-off

## Document status

- Prompt/task: `W2-REVIEW-001` / W2-12
- Column L content draft: **Completed under approved Column L**
- Owner content review: **Completed**
- Column M documentation approval: **APPROVED FOR COLUMN M DOCUMENTATION FINALIZATION — W2-REVIEW-001**
- Column N final owner approval: **Approved**
- W2-12 gate state: **Verified and Approved**
- Week 3 handover: **Pending owner tracker/prompt reconciliation, a clean committed baseline and resolution or explicit reconciliation of W1-08**
- W2-12 tracker state: **Done — owner-reconciled after successful Column N closure**
- Tracker update responsibility: **Owner**

This record closes the bounded W2-12 review without expanding the approved local-only evidence. W2-12 is owner-reconciled and W2-13 is final-approved; remaining pre-Week-3 actions are tracker/prompt reconciliation, the clean committed baseline and the separate W1-08 prerequisite.

## Approved Week 2 baseline

The approved local baseline consists of:

- Provider-neutral document, chunk, query and retrieval-domain models.
- `VectorStore` protocol and deterministic fake.
- Internal-only Qdrant foundation.
- Qdrant adapter and injected OpenSearch boundary.
- Tenant, clearance, classification and role/group isolation.
- Immutable MiniLM embedding contract.
- Secure deterministic ingestion pipeline.
- PII redaction and quarantine controls.
- Top-five local retrieval proof.
- Controlled rollback to the known-good expectation.
- Complete local task removal and zero-residue verification.
- Week 2 owner learning and teach-back.

This baseline is local Linux/AMD64 evidence. It is not production, cloud, live OpenSearch, AWS or compliance evidence.

## Retrieval scope

- Q1–Q4: **PASS** — the expected authorized source appeared within the top five.
- Q5: retrieval-only recording.
- Final safe-abstention proof: **NOT RUN**.
- LLM answer generation: **NOT RUN**.
- Citation generation: **NOT RUN**.
- Production semantic-quality proof: **NOT RUN**.

Top-five expected-source presence does not prove generated-answer correctness, citation completeness, faithfulness or safe abstention.

## Authorization boundary

- Qdrant remains internal-only on the logical `qdrant_internal` network.
- No Windows host, LAN or public port is approved.
- Active search filters are tenant identity, clearance-derived classifications, role/group access-control lists, PII status and ingestion status.
- Source identity and document version are provenance, deterministic-identity and lifecycle fields; they are not current search-authorization filters.
- Unauthorized contexts return zero protected chunks within the approved evidence scope.
- Returned-result validation provides defence in depth.
- The model is not trusted to enforce access control.

## PII limitation

- W2-003 implemented the approved PII policy and fail-closed behavior.
- W2-004 used `SyntheticPiiAnalyzer` for the bounded local control-flow proof.
- Real Presidio execution: **NOT RUN**.
- Production PII-detection-quality validation: **NOT RUN**.
- Quarantined content was absent within the approved local test scope.

Synthetic PII control-flow evidence must not be presented as production Presidio-quality evidence.

## Rollback

- **State N:** final known-good local retrieval configuration and expectations.
- **State N+1:** bounded, test-scoped, non-mutating expectation override.
- **Regression detection:** the controlled W2-004 regression detected the N+1 mismatch; its historical failure remains visible.
- **Rollback:** removing the override restored State N.
- **Post-rollback verification:** known-good retrieval, tenant isolation and quarantine absence passed within the approved W2-004 scope.
- Destroying the environment is teardown, not rollback.

Application/source-version rollback, production rollback, backup restore, disaster recovery and cloud rollback were **NOT RUN**.

## Teardown and residual resources

Approved W2-004 evidence records:

- Exact `w2_004_local_retrieval` collection and derived-vector removal: **PASS**.
- Qdrant and task runner container removal: **PASS**.
- Task network and named-volume removal: **PASS**.
- Local runner-image removal: **PASS**.
- Repository cache and generated-bytecode cleanup: **PASS**.
- W2-002 external model-cache removal and absence verification: **PASS**.
- Zero prohibited project-labelled task residue: **PASS**.

Accepted retained resources:

- External reusable project virtual environment.
- Disclosed immutable Qdrant and Python base images.
- Shared BuildKit cache for reusable build layers.

BuildKit numeric size is **NOT RECORDED — OWNER-ACCEPTED EVIDENCE GAP**. Its residual risk is undisclosed local disk consumption and possible future eviction or recreation. This local teardown is not cloud teardown; cloud teardown was **NOT RUN**.

## Accepted warnings and evidence gaps

- Starlette/FastAPI TestClient deprecation warning remains accepted and non-blocking for the recorded Week 2 scope.
- Direct dependency identities were approved, but no fully hashed transitive lock or production SBOM attestation exists.
- Real Presidio, production PII quality, live OpenSearch/AWS, production identity, performance, high availability and disaster recovery are not proved.
- Q1–Q4 prove only top-five expected-source presence; Q5 remains retrieval-only.
- Shared BuildKit cache size is not recorded.
- Historical retained-cache statements remain accurate for their task stages; the W2-002 model cache was later removed during W2-004 teardown.

Remaining open **INDETERMINATE** activities: None. Historical INDETERMINATE tool output remains preserved in its task evidence with the subsequent successful bounded rerun.

## Explicit NOT RUN scope

- Live Bedrock execution.
- Live OpenSearch execution.
- Live external model-provider execution.
- AWS deployment.
- Production deployment.
- Kubernetes deployment.
- Terraform deployment.
- Paid evaluation service execution.
- Real Presidio execution.
- LLM answer generation.
- Citation generation.
- Final safe-abstention validation.
- Production-scale performance testing.
- High availability and disaster recovery.
- Cloud rollback.
- Cloud teardown.

Bedrock and evaluation-provider inputs are deferred or mocked for this checkpoint. Any Week 3 live provider use requires a separate exact owner approval covering credentials, region, model, privacy, residency, cost, network and teardown.

## Gate decision and remaining handover boundary

**W2-12 — VERIFIED AND APPROVED**

The separately approved ADR, authorization and W2-001 component-document corrections are complete. `RAG-001` is consistently `In Progress`. Owner-executed targeted tests, consumer-contract tests, repository validation, the complete suite, Ruff, strict MyPy and repository-cleanliness verification passed. All three W2-REVIEW-001 manifest documents are closed together by this Column N action.

W2-12 is owner-reconciled as `Done`, and W2-13 is final-approved through its four-document closure. Week 3 must not begin until the owner reconciles the remaining tracker/prompt cells, establishes a clean committed baseline and resolves or explicitly reconciles W1-08. Live Bedrock, OpenSearch, LLM and paid evaluation remain separately approved activities and are not implied by this sign-off.

## Content-edit rollback

If this draft is rejected, remove only the two W2-REVIEW-001 CREATE documents after exact-path review and restore only the README section introduced with them under a new bounded Content Edit Approval. Do not alter historical Week 2 evidence. Keep W2-12 owner-managed and retain the approved local-retrieval baseline. No runtime rollback or teardown is involved.

## Final Owner Approval

- Prompt/task ID: `W2-REVIEW-001`
- Reviewer exact name: **Gyan Prakash Rai**
- Reviewer role: **Project Owner and Final Approval Reviewer**
- Exact owner decision: **Approved**
- Approval date and time/timezone: **2026-08-25 23:32:08 SGT (UTC+08:00)**
- Final status: **Verified and Approved**
- Documentation review status: **Approved; all three Column M manifest documents closed together**
- Owner-executed test status: **PASS** — targeted feature and consumer checks, complete suite, Ruff, strict MyPy, repository validation and cleanliness verification passed; expected skips/deselections and the accepted warning remain recorded
- Accepted warnings and risks: All warnings and risks already recorded in the three-document manifest are accepted; no additional items
- Evidence gaps and limitations: All manifest gaps and limitations remain accepted, including the unrecorded BuildKit cache numeric size; no additional items
- NOT RUN and INDETERMINATE acceptance: All manifest **NOT RUN** activities remain **NOT RUN**; none is converted to PASS; no remaining INDETERMINATE activity exists and historical evidence remains preserved
- Deferred actions and owners: All recorded deferrals remain open; responsible owner: **Gyan Prakash Rai**
- Deployment, rollback, teardown and residual-resource facts: Approved local-only evidence; production/cloud deployment **NOT RUN**; bounded local State N rollback passed while application/source/cloud rollback remains **NOT RUN**; local teardown passed; the external virtual environment, disclosed shared base images and shared BuildKit cache remain accepted, with BuildKit numeric size not recorded
- Conditions: Preserve historical results, warnings, limitations and NOT RUN work; close all three manifest documents together; only the owner updates Excel
- Next-task handover: Owner reconciles W2-12, completes and reconciles W2-13, then establishes a clean committed baseline before Week 3
- Tracker update responsibility: **Owner — Gyan Prakash Rai**

## W2-13 Final Owner Approval and Week 2 learning closure

- Prompt/task: `WEEKLY-LEARN-001` / W2-13
- Canonical learning record: `docs/learning/W2-learning-review.md`
- Column M state: **Reviewed and closed through the complete four-document manifest**
- Reviewer: **Gyan Prakash Rai — Project Owner and Final Approval Reviewer**
- Owner teach-back: **PASS**
- Owner decision: **FINAL APPROVAL AFTER OWNER TEACH-BACK — APPROVED**
- Approval timestamp: **2026-08-25 23:59:08 SGT (UTC+08:00)**
- Column N final status: **APPROVED FOR USER TRACKER UPDATE — W2-13**
- Runtime impact: None; this is a learning and documentation-only handover
- Prior W2-12 approval: Preserved unchanged

The W2-13 record summarizes the complete Week 2 business outcome, local-retrieval architecture, decisions, historical failures, evidence limits, rollback, teardown and interview preparation. It does not replace the detailed W2-11 architecture record at `docs/architecture/local-retrieval.md` and does not expand any PASS, deployment or cloud claim.

W2-13 is final-approved after the owner-reviewed teach-back and complete four-document Column N closure. Week 3 still requires owner-managed tracker reconciliation, a clean committed baseline and resolution or explicit governing reconciliation of the separate W1-08 open control gap.

All recorded warnings, risks, evidence gaps, limitations, NOT RUN work and historical INDETERMINATE evidence remain unchanged. W2-13 ran no new test, deployment, rollback or teardown. Approved Week 2 deployment evidence remains local-only; State N rollback and local teardown passed; production/cloud deployment, application/source/cloud rollback and cloud teardown remain **NOT RUN**. The external virtual environment, disclosed shared base images and shared BuildKit cache remain accepted, with BuildKit numeric size not recorded.

### W2-13 Column M manifest

| Exact path | Classification | Column M state | Column N requirement |
|---|---|---|---|
| `docs/learning/W2-learning-review.md` | CREATE | Final-approved | Closed |
| `docs/deployment-records/W2-signoff.md` | UPDATE | Final handover reconciled | Closed |
| `docs/test-evidence/W2/W2-REVIEW-001.md` | UPDATE | Downstream handover reconciled | Closed |
| `docs/test-evidence/README.md` | UPDATE | Final learning record indexed | Closed |

Tracker update responsibility: **Owner — Gyan Prakash Rai**.
