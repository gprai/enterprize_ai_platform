# Test Evidence

This directory explains how the `enterprise-ai-platform` project records owner-executed test results for business and technical review.

## Business purpose

Test evidence gives the owner a reliable record of what was checked before approving work. It prevents a successful local test from being confused with a deployment, a cloud test, or final business acceptance.

## Result meanings

- **PASS** means the owner ran the stated check and the supplied transcript showed the expected successful result.
- **FAIL** means the owner ran the check and the supplied transcript showed at least one failure.
- **NOT RUN** means the check was deliberately not executed or was outside the approved scope.
- **INDETERMINATE** means the supplied facts cannot prove whether an event occurred.
- **Pending** means an approval or owner decision is still required.

An **evidence metadata record** is a small JSON summary containing the command description, timestamp, Git state, environment, result, and report path. It is not the full test transcript. A **redacted** record excludes secrets and document content.

## Owner-controlled evidence process

1. Codex writes only approved automated test code.
2. The owner executes installation, testing, cleanup, deployment, rollback, and teardown commands.
3. The owner supplies the resulting transcript.
4. Codex records only facts supported by that transcript after Column M Document Writing Approval.
5. Column N Final Approval remains a separate owner decision.

The evidence recorder prints JSON to standard output, also called **stdout**, and does not create a report file. Narrative evidence files in this directory require separate Column M approval.

## Security and privacy rules

- Never record credentials, API keys, bearer tokens, private document content, prompts containing private data, or unrestricted absolute report paths.
- AWS and paid tests remain opt-in and require explicit owner approval.
- A local PASS does not prove production readiness, deployment success, data-residency compliance, or live integration availability.
- Failures and skipped work must remain visible; they must not be silently converted into a PASS.

## Evidence records

- [W1-001](W1-001.md) — approved aggregate repository-foundation evidence; final task approval recorded, with deployment and live lifecycle work NOT RUN.
- [W1-002](W1-002.md) — approved aggregate typed-configuration and local application-foundation evidence, preserving the dependency-install summary gap and accepted warning.
- [W1-003](W1-003.md) — local testing structure, deterministic providers, opt-in markers, redacted stdout metadata, and cleanliness controls.
- [W1-004](W1-004.md) — owner-gated lifecycle controls, offline planning, fail-closed cleanliness verification, remediation history, and owner-executed validation.
- [W1-03 repository layout](W1-03-layout.txt) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-04 feature matrix](W1-04-feature-matrix.json) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-05 typed configuration](W1-05-config.txt) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-06 test foundation](W1-06-tests.json) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-07 Makefile controls](W1-07-make.txt) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-08 pre-commit and secret scanning](W1-08-precommit.txt) — **OPEN CONTROL GAP — implementation and verification not completed**; also a retrospective evidence-gap reconciliation, not contemporaneous command output.
- [W1-09 Terraform roots](W1-09-roots.txt) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-10 platformctl](W1-10-platformctl.txt) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W1-11 cleanup verification](W1-11-cleanup.json) — **Retrospective evidence-gap reconciliation — not contemporaneous command output**.
- [W2-001](W2-001.md) — retrieval contracts, vector-store adapters, tenant isolation, internal-only Qdrant testing, remediation history, and teardown evidence.
- [W2-002](W2-002.md) — bounded embedding contracts, deterministic fake testing, immutable real-model verification, offline CPU inference, remediation history, and retained-cache evidence.
- [W2-003](W2-003.md) — secure local ingestion, deterministic identity, PII-before-embedding controls, offline tokenizer verification, exact-version compensation, remediation history, and cleanliness evidence.
- [W2-004](W2-004.md) — internal-only local retrieval, authorized top-five results, tenant isolation, regression and known-good rollback validation, exact collection removal, Docker teardown, external model-cache removal, and zero-residue evidence.
- [W2-REVIEW-001](W2-REVIEW-001.md) — **Column L content draft completed; owner content review completed; Column M documentation approval granted; Column N final approval pending; W2-12 remains In Progress; Week 3 handover is conditional and Week 2 sign-off is not final.**
- [W2 Week 2 sign-off](../deployment-records/W2-signoff.md) — **Column L content draft completed; owner content review completed; Column M documentation approval granted; Column N final approval pending; W2-12 remains In Progress; Week 3 handover is conditional and Week 2 sign-off is not final.**

W2-001 also has bounded component evidence for its [models](W2-01-models.txt), [vector-store contract](W2-02-vector-contract.txt), [Qdrant integration](W2-03-qdrant.txt), [adapters](W2-04-adapters.txt), and [tenant isolation](W2-08-isolation.txt). These records describe owner-executed local checks; they are not deployment or live-cloud evidence.

W2-002 has bounded component evidence for its [W2-05 embedder](W2-05-embedder.txt). It records owner-executed fake-provider checks, immutable model download and integrity verification, offline real-model execution, repository cleanliness, and the intentionally retained external model cache. W2-002 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**. The owner did not supply a reviewer name or approval date, so neither is recorded.

W2-003 has bounded component evidence for [W2-06 ingestion](W2-06-ingestion.txt) and [W2-07 PII](W2-07-pii.txt). These records cover owner-executed local ingestion, privacy, rollback and cleanliness checks. W2-003 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on 2026-08-25 at 13:45 SGT (UTC+08:00).

W2-001 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**. The owner did not supply a reviewer name or approval date, so neither is recorded. The owner-managed Excel tracker update remains **Pending**.

# W1-003 final approval

W1-003 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from Gyan Prakash Rai on 2026-08-22. Its approved baseline is the owner-tested repository testing and evidence foundation recorded in `docs/test-evidence/W1-003.md`.

Column N authorizes only bounded closure of documentation already approved under Column M. After documentation closure, the owner—not Codex—updates the Excel tracker.

This approval does not mean that AWS or paid tests, live integrations, deployment, rollback execution, or cloud teardown were completed; those activities remain **NOT RUN** because they were outside W1-003. The accepted Starlette/TestClient warning, two deferred W1-001 Ruff findings, retained external virtual environment, and indeterminate initial DeepEval telemetry or update-check activity remain recorded limitations.

## W1-004 final approval

W1-004 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from G P Rai on 2026-08-22. Its approved baseline is the owner-tested, owner-gated lifecycle foundation recorded in `docs/test-evidence/W1-004.md`. The approved local testing scope passed after the documented teardown and Ruff remediations. The offline plan-intent check passed and explicitly reported that Terraform plan was **NOT RUN**.

AWS cleanliness remains **INDETERMINATE** because the required AWS inventory provider was unavailable; exit code `3` is the approved fail-closed result for that condition. AWS and paid tests, live integrations, deployment, rollback execution, Terraform apply/destroy, and cloud teardown remain **NOT RUN** and were not converted into successful outcomes by final approval. The retained external virtual environment and non-blocking Starlette/TestClient warning remain accepted limitations.

The next task may rely on W1-004's approved local lifecycle contracts, deterministic test foundation, provider-free Terraform roots, and fail-closed offline behavior. It must obtain separate approval before relying on live AWS state, deployment success, rollback execution, or cloud cleanliness. The owner updates the Excel tracker after this bounded documentation closure.

## Week 1 evidence reconciliation status

Nine original step-level files for W1-03 through W1-11 were unavailable. The indexed step records were created later to disclose the gap and map supported historical outcomes to approved aggregate W1-001 through W1-004 evidence. They do not recover or recreate original command output, and retrospective execution was **NOT RUN**. The current W2-expanded repository was not represented as the W1 baseline.

Week 1 evidence completeness is **QUALIFIED**. W1-08 remains an **OPEN CONTROL GAP** and requires a new bounded implementation task plus Code Edit Approval before W3-001 or any production/cloud deployment, whichever occurs first. Local and mocked results do not prove live AWS, deployment, rollback, teardown, or production behavior.

### Week 1 reconciliation — Final Owner Approval

- Column M manifest: **18 documents — 9 retrospective CREATE records and 9 corrected UPDATE records**.
- Column N documents closed: **18**.
- Reviewer: **Gyan Prakash Rai — Project Owner, Learner and Approval Reviewer**.
- Current reconciliation decision: **APPROVED WITH QUALIFICATIONS**; documentation review **APPROVED**.
- Approval timestamp: **2026-08-25 21:38:20 SGT (UTC+08:00)**.
- Evidence completeness: **QUALIFIED**.
- W1-08 status: **OPEN CONTROL GAP** — implementation and verification not completed.
- Accepted limitations: missing contemporaneous records, historical warnings/gaps, retained external environment, dirty W2-era baseline excluded from W1 evidence, and local/mock proof not establishing live behavior.
- NOT RUN and INDETERMINATE classifications remain exactly as recorded in the linked evidence.
- Final reconciliation status: **APPROVED FOR USER TRACKER UPDATE — WEEKLY-LEARN-001 — WEEK 1 CONTROL FOUNDATION**.
- Tracker reconciliation and update responsibility: **Owner — Gyan Prakash Rai**.

## W2-001 final approval

W2-001 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**. Its approved baseline is the owner-tested local retrieval foundation recorded in `docs/test-evidence/W2-001.md`, including the retrieval models and vector-store contract, deterministic fake, injected OpenSearch boundary, tenant-isolation controls, internal-only Qdrant test architecture, immutable runner identity, least-privilege controls, passing local verification, and zero project-labelled Docker residue after teardown.

Final approval accepts the documented local-scope limitations and non-blocking warnings: the Starlette/FastAPI TestClient deprecation warning, BuildKit's constant-platform warning for the intentionally explicit Linux/AMD64 constraint, Compose's `--progress` placement advice, repository-approved dependency-family bounds rather than a fully locked transitive graph, and the absence of vulnerability-scan evidence. The reviewer name and approval date were not supplied and remain an evidence gap.

Live AWS/OpenSearch, production identity and policy integration, real sensitive-data processing, cloud or production deployment, registry push, production backup/restore and scaling, application or source rollback, cloud rollback/teardown, and cloud-cleanliness proof remain **NOT RUN**. Final approval does not convert those items into PASS.

The owner-executed teardown removed the W2-001 container, task volume, internal network, and locally built runner image. The reusable external virtual environment and shared immutable Python and Qdrant images or build cache may remain intentionally; they are not project-labelled Compose residue.

The next task may rely on the approved local retrieval contracts, tenant-isolation behavior, deterministic offline testing, injected OpenSearch boundary, and the internal-only Qdrant test pattern. It must obtain separate owner approval and produce new evidence before relying on live OpenSearch/AWS behavior, deployment, rollback, production security, or compliance. The owner updates the Excel tracker after this documentation closure.

## W2-002 final approval

W2-002 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED**. Its approved baseline is the owner-tested local embedding foundation recorded in `docs/test-evidence/W2-002.md` and `docs/test-evidence/W2-05-embedder.txt`: deterministic fake behavior, the bounded embedding contract, immutable model identity and artifact integrity, offline CPU-only real-model execution, process-wide concurrency control, passing local verification, and repository cleanliness.

Final approval accepts the documented local-scope limitations and evidence gaps. The Starlette/FastAPI TestClient warning and Hugging Face unauthenticated-rate-limit warning remain accepted and non-blocking. A fully locked transitive dependency graph, vulnerability scan, software bill of materials, reviewer name, and approval date were not supplied.

Qdrant mutation, collection creation, ingestion, AWS/OpenSearch, cloud and paid services, deployment, production identity integration, real enterprise-data processing, application/source rollback, and cloud rollback or teardown remain **NOT RUN**. Final approval does not convert those activities into PASS.

At W2-002 closure, the verified cache at `E:\AI\.model-cache\enterprise_ai_platform\W2-002` was intentionally retained through W2-06 and W2-07. Temporary MyPy data and real-model environment variables were removed. The retained cache was later removed and verified absent during the owner-approved W2-004 teardown.

The next tasks may rely on the approved embedding interface, deterministic fake, verified 384-dimensional normalized vectors, offline CPU execution, immutable snapshot and retained-cache prerequisite. They may not infer approval or evidence for ingestion, vector-store mutation, cloud integration, deployment, production data handling or compliance. The owner updates the Excel tracker after this bounded documentation closure.

## W2-003 final approval

W2-003 received **FINAL APPROVAL AFTER OWNER TEST — APPROVED** from Gyan Prakash Rai, Project Owner and Final Approval Reviewer, on 2026-08-25 at 13:45 SGT (UTC+08:00). Its final status is **APPROVED WITH RECORDED WARNINGS, RISKS, EVIDENCE GAPS, LIMITATIONS AND DEFERRED INTEGRATIONS**. The approved baseline is the owner-tested secure local ingestion and PII-gating implementation recorded in `docs/test-evidence/W2-003.md`, `docs/test-evidence/W2-06-ingestion.txt` and `docs/test-evidence/W2-07-pii.txt`.

The final local suite passed after the documented remediations: 239 passed, 3 skipped, 3 deselected, 9 subtests passed and 1 warning. Historical failures remain recorded. The Starlette/FastAPI TestClient warning is accepted as a non-blocking limitation; its remediation was **NOT RUN**. No vulnerability scan, software bill of materials or fully locked transitive dependency graph was supplied. Local fake and offline-tokenizer evidence does not prove production ingestion, identity integration, compliance or cloud readiness.

Real Qdrant ingestion/deletion, OpenSearch/AWS, W2-003 real MiniLM embedding, real Presidio NLP, deployment, actual application/source rollback, Docker or cloud teardown, production compliance validation and cloud-cleanliness proof remain **NOT RUN**. Fake-boundary exact-version rollback tests passed. Temporary MyPy caches and tokenizer environment variables were removed, and repository-local residue checks passed.

The reusable external virtual environment remains, including pypdf `6.16.2`. At W2-003 closure, the verified W2-002 model cache at `E:\AI\.model-cache\enterprise_ai_platform\W2-002` was intentionally retained through W2-06 and W2-07. It was later removed and verified absent during the owner-approved W2-004 teardown.

The next task may rely on W2-003's approved deterministic identity, strict manifest and PII-policy validation, PII-before-embedding boundary, provider-neutral contracts, offline tokenizer compatibility, exact-version compensation and repository-cleanliness evidence. It must obtain separate owner approval and evidence before relying on live vector stores, OpenSearch/AWS, production identity, real Presidio, deployment, production rollback, cloud teardown or compliance. Tracker update responsibility: **Owner — Gyan Prakash Rai**.

## W2-004 final approval

W2-004 received **APPROVED FOR FINAL DOCUMENTATION CLOSURE — W2-004** from Gyan Prakash Rai, Project Owner and Approval Reviewer, on 2026-08-25 at 17:52:46 SGT (UTC+08:00). Its task evidence is recorded in [W2-004](W2-004.md), with machine-readable retrieval evidence in [W2-09 retrieval](W2-09-retrieval.json). The approved rollback and resource-cleanliness records are maintained in `docs/rollback-records/W2-local.md` and `docs/resource-cleanliness/W2-local.json`.

The owner-executed local evidence records passing affected and complete suites, Ruff, MyPy, repository validation, Compose configuration, runner build and inspection, ingestion, authorized query and isolation, known-good rollback validation, exact collection removal, task-owned Docker teardown, external model-cache removal, teardown tests and zero-residue verification. The controlled regression's historical failure remains visible and is not converted into an ordinary PASS.

Production/cloud deployment, registry push, live AWS/OpenSearch, Terraform, Kubernetes, real Presidio, production PII-quality validation, paid model/API use, application/source rollback, cloud rollback/teardown, LLM answer generation, citations, final Q5 safe abstention, Week 3 cited-RAG testing and fully hashed lock creation were **NOT RUN**. **INDETERMINATE: None.** The Starlette/FastAPI warning is accepted as non-blocking. Local-only Linux/AMD64 scope, no fully hashed dependency lock or production SBOM, no real Presidio, no generated-answer/citation/safe-abstention proof and no semantic claim beyond Q1–Q4 top-five checks remain accepted limitations.

Qdrant remained internal-only with no Windows host, LAN or public port. The external project virtual environment and disclosed immutable Qdrant/Python base images were retained. Shared BuildKit cache was retained for reusable local Docker build layers; numeric size is **NOT RECORDED — OWNER-ACCEPTED EVIDENCE GAP** under the owner's 2026-08-25 17:57:55 SGT waiver. Residual risk is undisclosed local disk use and future eviction or recreation. Gyan Prakash Rai owns its future measurement or removal. No W2-004 project-labelled runtime, collection, network, volume, runner image, process, repository cache, bytecode or temporary residue is accepted.

### W2-004 Final Owner Approval

- Prompt/task ID: `W2-004`
- Reviewer: Gyan Prakash Rai
- Reviewer role: Project Owner and Approval Reviewer
- Decision: **APPROVED FOR FINAL DOCUMENTATION CLOSURE — W2-004**
- Approval timestamp: 2026-08-25 17:52:46 SGT (UTC+08:00)
- BuildKit waiver timestamp: 2026-08-25 17:57:55 SGT (UTC+08:00)
- Final status: **APPROVED FOR USER TRACKER UPDATE — W2-004**
- Code and documentation review: owner-tested bounded implementation and all five Column M documents approved and closed
- Owner-executed tests: local suites, quality gates, ingestion/query/isolation, controlled regression, known-good rollback, exact collection removal and cleanup completed with historical failures preserved
- Accepted risks, gaps and limits: local-only Linux/AMD64 proof; synthetic PII analyzer; Q1–Q4 top-five scope; Q5 retrieval-only scope; dependency/SBOM gap; retained shared resources; BuildKit numeric-size waiver
- NOT RUN: all activities listed in the W2-004 task record, including real Presidio, production/cloud/AWS/OpenSearch/Terraform/Kubernetes, answer/citation/abstention and application/source/cloud rollback
- INDETERMINATE: None
- Deployment, rollback and teardown: bounded local Compose execution, State N recovery and task cleanup passed; production deployment and rollback were **NOT RUN**
- Deferred actions and owner: Gyan Prakash Rai owns ADR-003/ADR-006 correction before W3-001, dependency/supply-chain hardening, real Presidio validation, Week 3 answer/citation/abstention proof, later cloud integration and future BuildKit measurement/removal
- Conditions: documentation-only reconciliation of all five manifest documents; historical outcomes and limitations remain unchanged
- Next-task handover: local retrieval and authorization are approved dependencies. The next task may not infer real Presidio, generated answers, citations, final safe abstention, deployment or cloud readiness; the W2-002 model cache has been removed.
- Tracker update responsibility: Owner
