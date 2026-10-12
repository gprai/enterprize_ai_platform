# Week 3 Sign-off Record — Cited RAG, Evaluation, Guardrails and Rollback

## Document control

| Field | Value |
| --- | --- |
| Tracker checkpoint | `W3-12` |
| Tracker feature | `W3-REVIEW-001` |
| Business checkpoint | Approve cited RAG and its quality gate before adding agent behavior |
| Evidence path | `docs/deployment-records/W3-signoff.md` |
| Current document status | **FINAL WEEK 3 SIGN-OFF — APPROVED** |
| Completed work | W3-001, W3-002, W3-003 and W3-004 |
| Open work | None for W3-12; later agent implementation, live validation and production work remain separately governed |
| Final reviewer | Gyan Prakash Rai |
| Final approval time and timezone | `2026-08-27 22:35:21 SGT` (`UTC+08:00`) |

This document is the Week 3 checkpoint record. All four Week 3 implementation tasks now have final-approved local evidence. This record does not itself authorize deployment, live-provider operation, production release or agent behavior, and it does not replace the detailed task evidence.

## Executive business summary

Week 3 turns the retrieval foundation from Week 2 into a controlled question-answering system that can:

- answer from authorized evidence and cite the source;
- refuse safely when evidence is missing, conflicting, invalid or unauthorized;
- measure quality and security consistently against approved cases;
- reject invalid inputs and suppress unsafe generated output;
- detect a harmful RAG configuration change and restore the approved configuration.

The business value is confidence with evidence. The organization does not need to trust an AI answer merely because it sounds convincing. It can check where the answer came from, prove that access controls were respected, measure regressions, block unsafe behavior, and recover from a bad configuration change. The local Week 3 foundation and rollback evidence are approved; agent behavior still requires the separate W3-12 checkpoint decision and any later implementation approval.

## Week 3 implementation status

| Task | What it delivers | Current evidence status | Week 3 sign-off effect |
| --- | --- | --- | --- |
| W3-001 — Cited RAG | Authorized retrieval, grounded answers, exact citations, safe abstention and fail-closed provider handling | Implemented, owner-tested and final-approved | Closed |
| W3-002 — Evaluation and quality gate | A deterministic 39-case examination, hard security gates, repeat reports and an immutable known-good baseline | Implemented, owner-tested, final-approved and baseline promoted | Closed |
| W3-003 — Guardrails | Input validation, injection-as-untrusted-data handling, zero tool execution, unsafe-output suppression and redaction checks | Implemented, owner-tested and final-approved | Closed |
| W3-004 — RAG configuration rollback | Detect a controlled N+1 regression, atomically restore known-good N, prove recovery and clean up scoped runtime state | Implemented, owner-tested, rollback-drilled, documented and final-approved | Closed |

## W3-001 — Cited RAG acceptance recap

### Business outcome

Users receive an answer only when the system has sufficient authorized evidence. Each answer cites the supplied source. If evidence is unavailable, conflicting, unauthorized, or the provider output is invalid, the system returns a safe abstention or content-free error instead of inventing an answer.

### Technical outcome

- Retrieval results are filtered by tenant, clearance and ACL before use.
- The provider receives only authorized evidence.
- Returned citations must match evidence actually supplied to the provider.
- Missing, fabricated, version-mismatched or unsupplied citations are suppressed.
- Conflicting document versions fail closed.
- Provider failures and malformed output do not expose prompts, retrieved text or provider responses.
- Normalized results contain the minimum safe information needed by downstream consumers.

### Approved verification facts

| Check | Result |
| --- | --- |
| Ruff | PASS |
| Strict MyPy | PASS |
| Scoped tests | 118 passed; 1 AWS/paid test deselected |
| Complete ordinary suite at closure | 344 passed; 7 skipped; 4 deselected |
| Live Bedrock/model evaluation | NOT RUN |
| Deployment/cloud lifecycle | NOT RUN |
| Network/provider activity and cost | None; USD 0 |

## W3-002 — Evaluation and known-good baseline acceptance recap

### Business outcome

RAG quality and security are judged by repeatable evidence instead of informal review of a few answers. A future candidate can be compared with an immutable owner-approved result.

### Technical outcome

- The golden dataset contains 39 ordered cases: 24 `ANSWERED`, 12 `ABSTAINED` and 3 `ERROR`.
- Retrieval-quality cases measure Recall@5 and report MRR.
- Answered facts, abstention reasons, expected errors and citations are checked deterministically.
- Tenant, clearance, ACL, prompt-injection and invalid-citation controls are covered.
- Candidate and repeat reports passed the absolute quality and security gates and matched deterministically.
- The owner promoted the accepted result to the immutable W3-002 baseline.

### Approved identity and verification facts

| Item | Approved fact |
| --- | --- |
| Baseline path | `configs/eval/baselines/w3-002-v1.json` |
| Baseline SHA-256 | `4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f` |
| Dataset | Q1–Q39; 24 answered, 12 abstained, 3 expected errors |
| Candidate evaluation | PASS |
| Repeat evaluation | PASS |
| Absolute/security gates | PASS |
| Complete ordinary suite at closure | 393 passed; 7 skipped; 4 deselected; 10 subtests |
| Live model/judge evaluation | NOT RUN |
| Real performance/capacity validation | NOT RUN |
| Deployment/cloud lifecycle | NOT RUN |
| Network/provider activity and cost | None; USD 0 |

The historical candidate reports correctly retain their original `NO_APPROVED_BASELINE` status. Baseline promotion accepted their exact deterministic evidence as the future comparison authority; it did not rewrite the historical reports or rerun evaluation.

## W3-003 — Guardrail acceptance recap

### Business outcome

Malformed or excessive input is stopped before it can consume retrieval or provider resources. Retrieved instructions are treated as untrusted data. Unsafe or invalid generated output is suppressed without leaking the input, retrieved content, prompt or provider response.

### Technical outcome

- The existing RAG boundary accepts `Query` callers and validates raw `str` input.
- Allowed content type is `text/plain` and the maximum input length is 10,000 Unicode characters.
- Invalid input raises the safe code `guardrail_input_invalid` before retrieval and provider invocation.
- Prompt-injection text is not handled by brittle lexical blocking; it remains untrusted content subject to authorization, citation and output validation.
- No tool described by user input, retrieved evidence or provider output is executed.
- Q30 preserves one fake-provider call followed by safe `invalid_generated_citation` suppression.
- Runtime logging was not added; tests prove captured logs are empty and normalized results/errors do not contain raw synthetic secret or PII sentinels.
- The optional vendor guardrail remains an interface-only, disabled local boundary with no dependency or network activity.

### Approved verification facts

| Check | Result |
| --- | --- |
| Final complete ordinary suite | 439 passed; 7 skipped; 4 deselected; 10 subtests; 1 warning |
| Historical defects | Two failures preserved in evidence and remediated before final approval |
| Live/vendor guardrail evaluation | NOT RUN |
| Deployment/cloud lifecycle | NOT RUN |
| Network/provider activity and cost | None; USD 0 |

## W3-004 — RAG configuration rollback acceptance recap

### Business purpose

W3-004 proves that a RAG configuration change which makes answers worse or unsafe can be detected and reversed to the exact approved W3-002 configuration. This is a configuration rollback drill only. It does not roll back an application release, infrastructure, production data, Qdrant, OpenSearch or cloud resources.

### Approved and executed drill

- `N` is the immutable known-good RAG identity tied to the approved W3-002 baseline and its transitive producer identities.
- `N+1` is a controlled synthetic configuration whose fake provider creates the exact approved Q1/Q2 invalid-citation regression.
- Activation uses a drill-only `active.json`, an exclusive writer lock, compare-and-swap protection and same-directory atomic replacement.
- The drill detected the N+1 regression and retained the failed regression report for owner-controlled archival.
- Rollback restored N without silently falling back during evaluation.
- Restored evaluation proved the approved absolute gates and baseline comparison again.
- Reports were no-overwrite and content-safe; exactly four byte-identical files were archived externally for 180 days before approved repository-local cleanup.
- The drill used no Qdrant, OpenSearch, Docker, API, live model, Bedrock, network or cloud lifecycle activity.

### Owner-executed implementation and quality evidence

| Check | Final result |
| --- | --- |
| Tool identity | PASS — Python 3.13.7, Pytest 9.1.1, Ruff 0.16.4, MyPy 1.20.2 and Pydantic 2.13.4 |
| Approved implementation manifest | PASS — 17 CREATE, 11 UPDATE, 0 DELETE and 0 unexpected implementation paths |
| Ruff | PASS — exact approved scope |
| Strict MyPy | PASS — no issues in 10 source files |
| Isolated remediated security test | PASS — 1 passed |
| Focused W3-004 and changed-consumer suite | PASS — 56 passed and 10 subtests passed |
| Complete ordinary suite | PASS — 465 passed, 7 skipped, 4 deselected, 10 subtests passed and 1 warning |
| Platform contract validation | PASS |
| Identity and protected-resource validation | PASS — W3-002 baseline, reports, dataset and configuration hashes remained exact |
| Known-good N initialization | PASS — generation 1 |
| Synthetic N+1 activation | PASS — generation 2 |
| Expected regression detection | PASS — absolute, baseline-comparison and overall status `FAIL`; `release_eligible=false` |
| Q1/Q2 invalid-citation control | PASS — both abstained safely; one provider call, zero citations and valid usage retained |
| Atomic rollback | PASS — known-good N restored at generation 3 |
| Restored evaluation | PASS — absolute, baseline-comparison and overall status `PASS`; `release_eligible=true` in the approved local scope |
| Final redacted rollback record | PASS |
| External archive | PASS — exactly four byte-identical files retained outside the repository for 180 days |
| Repository-local cleanup and zero-residue verification | PASS |
| Column M documentation closure | PASS — four approved documents reconciled together |
| Column N owner approval | APPROVED — `2026-08-27 17:31:21 SGT` |

The seven skipped and four deselected activities remain **NOT RUN** and were not converted to PASS by the ordinary-suite result.

### Preserved historical outcomes

1. Ruff initially found one import-order failure; the approved correction and exact rerun passed.
2. MyPy initially found one tuple-inference mismatch and one redundant cast; the approved corrections and exact rerun passed.
3. The first focused run recorded 1 failure and 55 passes because a security test captured a Windows `asyncio` proactor DEBUG message; the bounded test-only correction, isolated rerun and full focused rerun passed.
4. The first regression-report display was INDETERMINATE because it read the wrong JSON level; the corrected display proved `ABSOLUTE=FAIL` as designed.
5. One archive-inventory display failed because `Join-String` was unavailable; the compatible `-join` rerun proved the exact four-file inventory.

All historical failures and the resolved INDETERMINATE observation remain evidence. Remaining open INDETERMINATE activities: none.

### Closed W3-004 documentation manifest

| Action | Path | Purpose |
| --- | --- | --- |
| CREATE | `docs/rollback-records/W3-rag.md` | Human-readable rollback chronology, identities, results, recovery and lifecycle record |
| CREATE | `docs/test-evidence/W3/W3-004.md` | Aggregate W3-004 implementation and verification evidence |
| CREATE | `docs/test-evidence/W3/W3-11-rag-rollback.txt` | Exact rollback acceptance evidence for tracker step W3-11 |
| UPDATE | `docs/test-evidence/README.md` | Index the W3-004 evidence without rewriting earlier approvals |

All four documents were owner-reviewed and closed together under Column N. The detailed lifecycle and artifact identities are recorded in `docs/rollback-records/W3-rag.md`.

### Final W3-004 owner approval

| Field | Approved fact |
| --- | --- |
| Prompt/task ID | `W3-ROLLBACK-001` |
| Reviewer | Gyan Prakash Rai |
| Reviewer role | Project Owner and Final Approval Reviewer |
| Decision | **FINAL APPROVAL AFTER OWNER TEST — APPROVED** |
| Approval time | `2026-08-27 17:31:21 SGT` |
| Final status | **APPROVED FOR USER TRACKER UPDATE — W3-ROLLBACK-001** |
| Conditions | Preserve every PASS, FAIL, NOT RUN, INDETERMINATE, warning, limitation, deferral and residual-resource fact; infer no production or cloud readiness from local synthetic evidence; only the owner updates Excel or mutates Git |

## Security, privacy, cost and operational boundaries

| Area | Week 3 position |
| --- | --- |
| Authorization | Tenant, clearance and ACL enforcement are mandatory hard boundaries |
| Grounding | Answers require sufficient authorized evidence and exact supplied citations |
| Invalid output | Unsafe, malformed and invalidly cited output is suppressed |
| Prompt injection | User and retrieved instructions are untrusted data; zero tool execution |
| Logging | No raw query, evidence, prompt, generated answer, secret sentinel or PII sentinel in logs/errors |
| External services | No live model, Bedrock, vendor guardrail, Qdrant/OpenSearch lifecycle or cloud operation is approved by this sign-off |
| Provider/network activity | None in the approved deterministic Week 3 evidence |
| Provider cost | USD 0 |
| W3-004 privacy | The normalized rollback record contains no raw prompt, evidence, generated answer, invalid citation, provider response, credential, secret or private tenant data |
| Production claim | None; the evidence proves local deterministic contracts, not production performance or live-model quality |

## Accepted limitations and deferred work

The following facts must remain visible and must not be relabelled as PASS:

- Live Bedrock/model evaluation is NOT RUN.
- Ragas or another external judge evaluation is NOT RUN.
- Real latency, capacity and production performance validation are NOT RUN.
- Deployed API, service and cloud lifecycle validation are NOT RUN.
- Vendor guardrail invocation is deferred.
- Positive production telemetry and retention policy are deferred to later work.
- The Week 3 deterministic tests use controlled fake providers and synthetic fixtures; they do not prove the semantic behavior of every live model.
- The existing Starlette/FastAPI TestClient deprecation warning remains unresolved; remediation is NOT RUN.
- Build, packaging, formatter, pre-commit, vulnerability-scan and software-bill-of-materials evidence was not supplied for W3-004.
- Local deterministic W3-004 release eligibility does not authorize a production release.

These limitations do not invalidate the completed local contracts for W3-001 through W3-004. They constrain what Week 3 may claim and what later release governance must still prove.

## Rollback, teardown and retained resources

| Item | Status |
| --- | --- |
| W3-001 rollback contract | Approved local automated evidence; no production rollback performed |
| W3-002 immutable baseline | Retained at its approved path and hash |
| W3-002 candidate/repeat reports | Retained as historical evidence; original statuses preserved |
| W3-003 rollback/cleanliness contracts | Approved local automated evidence; no vendor or production rollback performed |
| W3-004 RAG configuration rollback drill | PASS — controlled regression detected, N restored atomically and restored evaluation passed |
| W3-004 repository-local runtime reports/state | Cleanup PASS; independent zero-residue verification PASS; `reports/w3-004` removed |
| External W3-004 archive | PASS — four byte-identical files retained at `E:\AI\Enterprise_AI_Doc_Retrieval\reports\w3-004` for 180 days |
| Cloud resources created by Week 3 work | None recorded |
| Deployment | NOT RUN |
| Production teardown | NOT RUN |
| Other retained resources | Approved W3-002 baseline and reports plus the external Python virtual environment |

Open Excel processes, workbook lock files and uncommitted workbook changes are outside this code/evidence decision and are not Column L blockers or owner-decision fields.

## W3-12 owner teach-back and decision checkpoint

Before final sign-off, the owner should be able to explain the following in their own words:

1. Why an answer with a valid citation is safer than an uncited fluent answer.
2. Why authorization must be applied before evidence enters the provider prompt.
3. The difference between `ANSWERED`, `ABSTAINED` and `ERROR`.
4. Why citation precision is a hard 1.00 gate and security violations must be zero.
5. Why candidate PASS is different from promotion to an immutable known-good baseline.
6. Why prompt injection is treated as untrusted data and why arbitrary tool execution is forbidden.
7. What a RAG configuration identity contains and how a bad N+1 configuration can degrade answers without changing Qdrant, OpenSearch or application infrastructure.
8. How compare-and-swap, locking, atomic replacement, no-overwrite reports and exact identity hashes make rollback auditable.
9. Which live-model, performance, deployment and cloud claims remain unproven.
10. Why agent endpoints remain disabled until the Week 3 quality, security and rollback checkpoint is approved.

### Teach-back result

| Field | Owner-supplied value |
| --- | --- |
| Owner completed teach-back | **COMPLETED** |
| Reviewer assessment | **PASS — COMPLETED AND ACCEPTED** |
| Misunderstandings or follow-up learning | None recorded for W3-12 closure |
| W3-12 acceptance criterion met | **PASS — grounded answer or abstention works; security, regression and rollback checks passed in the approved deterministic local scope** |

## Final owner approval

W3-004 implementation, owner-executed verification, rollback evidence, documentation closure and task-specific owner approval are complete. The owner has completed the teach-back and approved the separate W3-12 Week 3 checkpoint as follows.

| Required approval fact | Owner-supplied value |
| --- | --- |
| Reviewer exact name | Gyan Prakash Rai |
| Reviewer role | Project Owner and Final Approval Reviewer |
| Exact decision | **APPROVED** |
| Approval date and time | `2026-08-27 22:35:21` |
| Timezone / UTC offset | `SGT` / `UTC+08:00` |
| Accepted warnings, risks and limitations | All warnings, risks, limitations and local/synthetic scope statements recorded in this document and the four task evidence closures are accepted |
| PASS facts accepted | All recorded final W3-001, W3-002, W3-003 and W3-004 PASS facts are accepted |
| FAIL facts accepted | Historical remediated failures and the intentional N+1 evaluation `FAIL` are accepted and preserved; none is relabelled or omitted |
| NOT RUN facts accepted | All recorded live-model, judge, performance, deployment, production, cloud, vendor and other NOT RUN activities remain NOT RUN and are accepted as limitations |
| INDETERMINATE facts accepted | Historical resolved INDETERMINATE observations remain preserved; remaining open INDETERMINATE activities: none |
| Evidence gaps | Live-provider semantics, real latency/capacity, deployment, production security/privacy/residency, cloud lifecycle, vendor guardrails and the unperformed build/security scans remain explicitly unproven |
| Deferred actions and responsible owners | Gyan Prakash Rai owns the recorded deferrals, external archive retention/deletion, future live and production validation, tracker reconciliation and Git mutation unless another owner is explicitly recorded |
| Deployment facts | Local, cloud and production deployment remain **NOT RUN**; this sign-off grants no production-release authority |
| Rollback facts | Local deterministic W3-004 identity rollback **PASS**; application/source, deployment, live-provider and cloud rollback remain **NOT RUN** |
| Teardown facts | Repository-local W3-004 cleanup and independent zero-residue verification **PASS**; Docker, service and cloud teardown remain **NOT RUN** because none was started or created |
| Residual resources and retention | Approved W3-002 baseline and reports, external Python virtual environment and the four-file W3-004 external archive remain retained; archive retention is 180 days under owner control |
| Approval conditions | Preserve every PASS, FAIL, NOT RUN, INDETERMINATE, warning, limitation, deferral and residual-resource fact; infer no production or cloud readiness from local synthetic evidence; later agent implementation and operation require separate approval |
| Agent behavior may begin | **APPROVED only for separately governed next-task design and implementation; no agent endpoint is implemented, deployed or activated by this sign-off** |

## Current decision

W3-001, W3-002, W3-003 and W3-004 are accepted as completed, owner-tested and final-approved local Week 3 building blocks. The W3-004 drill successfully used W3-002's immutable baseline as its known-good authority. The tracker acceptance evidence shows that grounded answer-or-abstention works and the required security, regression and rollback checks pass in the approved deterministic local scope.

The owner teach-back is completed and accepted. W3-12 is final-approved at `2026-08-27 22:35:21 SGT` (`UTC+08:00`). The owner may update the tracker. No deployment, production release, live-provider use or agent endpoint activation is implied.

**FINAL APPROVAL — WEEK 3 CHECKPOINT CLOSED — W3-REVIEW-001 / W3-12.**
