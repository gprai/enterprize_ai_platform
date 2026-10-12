# Week 2 — Local Retrieval Business, Architecture and Interview Learning Review

## Document control

- Prompt/task: `WEEKLY-LEARN-001` / W2-13
- Document classification: **Column N closed — final-approved W2-13 learning record**
- Detailed W2-11 technical authority: `docs/architecture/local-retrieval.md`
- Owner teach-back status: **PASS**
- Column N final approval: **FINAL APPROVAL AFTER OWNER TEACH-BACK — APPROVED**
- Runtime commands or tests executed by this learning task: **None**
- Tracker update responsibility: **Owner**

This is the canonical Week 2 business, architecture, decision and interview summary required by W2-13. It complements rather than replaces `docs/architecture/local-retrieval.md`: the architecture document is the detailed W2-11 technical explanation, while this record connects the complete Week 2 outcome to business value, evidence, lifecycle decisions and interview preparation.

## 1. Executive business summary

Week 2 established a governed local-retrieval foundation that turns approved enterprise documents into searchable, authorized evidence. The platform can validate and identify documents, apply PII policy before creating derived data, split content deterministically, create normalized local embeddings, store and retrieve vectors through an internal-only Qdrant boundary, filter results using authorization metadata, detect a bounded regression, restore the known-good state and remove task-owned resources.

The business outcome is not an unrestricted semantic-search demo. It is a controlled retrieval capability in which provenance, tenant isolation, privacy decisions, model identity, test evidence, rollback and teardown are explicit and reviewable. This reduces the risk of an AI answer using unapproved, cross-tenant or privacy-incompatible material.

## 2. Business use case and beneficiaries

The example use case is an internal enterprise knowledge system. Employees need relevant source material, but two people asking the same question may be authorized to see different documents. Retrieval therefore has to combine semantic relevance with tenant, clearance, role, group, PII-state and ingestion-state controls.

Primary beneficiaries are:

- Employees who need relevant approved source material.
- Security and privacy reviewers who need evidence that access is enforced before content leaves the retrieval boundary.
- Platform teams that need replaceable providers and deterministic lifecycle controls.
- Business owners who need measurable results, known limitations and reversible change.
- Architecture interviewers who expect an end-to-end explanation rather than isolated code details.

## 3. Architecture position

Week 2 sits between the Week 1 control foundation and Week 3 cited-answer generation. It produces authorized source candidates; it does not generate an answer or citation.

```text
Approved document and manifest
  -> validation, provenance and deterministic identity
  -> PII inspection: redact, allow or quarantine
  -> normalized token-based chunks
  -> immutable offline MiniLM embeddings
  -> provider-neutral VectorStore boundary
  -> internal-only Qdrant collection

Authorized question
  -> active, structurally valid authorization context
  -> question embedding under the same model contract
  -> adapter-applied metadata filters
  -> cosine-similarity search
  -> defence-in-depth result validation
  -> permitted top-five source candidates
```

Week 3 may consume those candidates to generate grounded answers, citations and safe abstention. Week 2 does not claim those downstream capabilities.

## 4. Producer-consumer responsibilities

| Producer or boundary | Output | Primary consumer | Required invariant |
|---|---|---|---|
| Document validation | Approved metadata and normalized source | Identity and PII policy | Required provenance, tenant and classification metadata are present |
| Deterministic identity | Stable document, version and chunk identities | Upsert, deletion and evidence | Same approved input produces the same identity |
| PII policy | Allowed, redacted or quarantined content state | Chunker and ingestion pipeline | Prohibited content stops before embedding or vector storage |
| Chunker | Ordered 200-token chunks with 25-token overlap | Embedding provider | Chunk identity and source/version provenance remain stable |
| Embedding provider | Normalized 384-dimensional vectors | VectorStore adapter | Model, revision, dimension and normalization match before query or mutation |
| Retrieval service | Validated request and embedded query | VectorStore | Authorization context is active and structurally valid |
| Qdrant adapter | Provider-specific filters and ranked candidates | Retrieval service | Filters constrain provider search before protected results can return |
| Result validation | Authorized retrieval results | Later answer/citation layer | Semantic similarity cannot grant access |

## 5. Approved embedding decision

The approved real model is `sentence-transformers/all-MiniLM-L6-v2` at immutable revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`. Its contract is 384 dimensions, normalized vectors, cosine-compatible similarity, CPU-only execution and offline loading from an explicitly approved external snapshot. Authentication tokens and remote-code trust are not used.

Ordinary unit, contract, feature and security tests use `FakeEmbeddingProvider`. The fake provides deterministic contract behavior without downloading or loading a model. It does not prove semantic quality. A separately controlled real-model test proved offline CPU operation and the approved dimension/normalization contract.

## 6. Cosine similarity in business terms

Cosine similarity compares the direction of two vectors. It helps rank chunks whose meaning is close to the question even when their wording differs. Because the approved vectors are normalized, the comparison is consistent with the collection contract.

Similarity is only a candidate-ranking mechanism. A high score does not prove that a chunk is correct, complete, authorized or sufficient to answer the question.

## 7. Chunking decision and trade-off

The governed baseline uses a maximum chunk size of **200 tokens** with **25 tokens of overlap**.

- Smaller chunks can improve precision but lose surrounding context.
- Larger chunks preserve context but may mix topics and reduce retrieval precision.
- Overlap preserves ideas that cross a boundary but increases vector count, storage and repeated-result risk.

The 200/25 setting is an approved starting point, not a permanent optimum. A future change requires new retrieval-quality comparison and re-ingestion evidence.

## 8. Authorization and metadata filtering

The active retrieval filters are:

- Tenant identity.
- Classifications permitted by the requester's clearance.
- Role and group access-control lists.
- PII status.
- Ingestion status.

The retrieval service validates that the authorization context is active and structurally valid, embeds the question and delegates through the provider-neutral `VectorStore` boundary. The Qdrant adapter constructs provider-specific metadata filters before vector search. Returned-result validation provides defence in depth.

Source identity and document version support provenance, deterministic identity, idempotent upsert, version-aware deletion and evidence traceability. They are not current query-authorization filters. Unauthorized contexts must receive zero protected chunks even when their questions are semantically similar to restricted content.

## 9. PII-before-embedding decision

PII inspection happens before chunking, embedding and vector storage because those outputs are derived data. Embedding first and deleting only the original source would leave other representations behind.

The approved control path either redacts supported information or quarantines prohibited content before vector creation. Quarantined content must not enter Qdrant or appear in evidence. Week 2 used `SyntheticPiiAnalyzer` to prove this control flow. Real Presidio execution and production PII-detection-quality validation remain **NOT RUN**.

## 10. Internal-only Qdrant boundary

Qdrant provides the real local vector-store boundary. It remains attached only to the logical Compose network `qdrant_internal`, with no Windows host, LAN or public port publication. Approved one-shot runners reach Qdrant using Docker service discovery.

The earlier host-port approach was rejected because the owner-selected architecture did not require host exposure. Internal-only networking reduces the reachable surface while retaining useful integration evidence.

## 11. Provider-neutral design and OpenSearch exit path

Business logic uses the `VectorStore` contract rather than Qdrant or OpenSearch SDK types. This keeps document, authorization and retrieval-domain behavior portable.

Provider neutrality does not make migration automatic. A future OpenSearch implementation must re-prove vector dimensions, similarity behavior, filter semantics, tenant isolation, deterministic ingestion, timeouts, retries, partial failures, performance, cloud credentials, residency, cost, backup, rollback and teardown. Live OpenSearch and AWS integration were **NOT RUN** in Week 2.

## 12. Evidence-backed Week 2 results

The approved task-stage evidence records:

- W2-001: retrieval models, vector contract, adapters, tenant isolation and internal-only Qdrant foundation passed within the recorded local scope.
- W2-002: deterministic fake embeddings, immutable model verification and offline CPU real-model inference passed.
- W2-003: secure local ingestion, deterministic identity, chunking, PII gating and offline tokenizer compatibility passed within their recorded scope.
- W2-004: local real-model/Qdrant ingestion, Q1–Q4 authorized top-five retrieval, isolation, controlled regression, State N recovery, exact collection removal and task-resource teardown passed.
- W2-REVIEW-001: producer-consumer contracts, repository validation, complete suite, Ruff, strict MyPy and repository-cleanliness checks passed after the final status and documentation reconciliations.

The latest recorded complete suite contained **261 passed, 7 expected skips, 3 deselected, 10 subtests and one accepted warning**. Counts from earlier task stages remain historical stage evidence and are not replaced by this later count.

## 13. Retrieval-quality result and limitation

- Q1–Q4: the expected authorized source appeared within the top five results.
- Stable ingestion did not create duplicate identities or point counts.
- Unauthorized contexts retrieved zero protected content.
- Quarantined content was absent within the approved local test scope.
- Q5: retrieval behavior was recorded only.

These results do not prove generated-answer correctness, citation faithfulness or safe abstention. LLM answer generation, citation generation and final Q5 safe-abstention validation remain **NOT RUN**.

## 14. Historical failures and remediation learning

Week 2 preserved historical failures instead of rewriting them as PASS. Examples included:

- Qdrant host publication failing under the internal-only Docker network design.
- Stale feature-matrix, validator and test-fixture contracts.
- Ruff import and API findings.
- A strict MyPy lambda inference finding.
- An outdated Sentence Transformer dimension API.
- A missing Docker build-context dependency.
- A missing approved model-blob host path.
- The intentionally introduced local-retrieval regression.

The learning is procedural as well as technical: stop on failure, inspect the complete producer-consumer surface, request one consolidated bounded approval, apply only the approved change, rerun owner-controlled evidence and preserve both the historical failure and the final outcome.

## 15. Rollback, teardown and recovery

Rollback restores a known-good capability. Teardown removes scoped resources. They are different controls.

The W2-004 rollback proof used:

- **State N:** the approved local retrieval configuration and expectations.
- **State N+1:** a bounded, test-scoped, non-mutating expectation override.
- **Detection:** the controlled regression rejected the N+1 expectation.
- **Rollback:** removing the override restored State N.
- **Verification:** health, idempotent ingestion, Q1–Q4 retrieval, authorization isolation and quarantine absence passed again.

Separate teardown removed the exact task collection and derived vectors, Compose container, internal network, named volume, local runner image, task-owned temporary data and repository-generated residue. The W2-002 external model cache was also removed and verified absent. Application/source rollback, production rollback and cloud rollback/teardown remain **NOT RUN**.

## 16. Security and privacy learning

- Authorization is enforced before protected results can leave the vector-store boundary.
- Semantic similarity never grants access.
- PII policy precedes derived-data creation.
- Qdrant is internal-only and has no host/public port.
- Credentials, raw protected content, prompts containing private data and unrestricted paths are excluded from evidence.
- Deterministic identity and provenance support exact deletion and auditability.
- Fake tests and local integration evidence are not presented as production security proof.

No live identity provider, production IAM integration, penetration test or production compliance validation was proved in Week 2.

## 17. Reliability, concurrency and operational learning

Deterministic identities and idempotent ingestion reduce duplicates and make deletion/version compensation explainable. Model, revision, dimension and normalization mismatches fail before query or mutation. Synchronous CPU inference runs outside the asynchronous event loop and is protected by a process-wide lock so overlapping model operations do not escape the approved concurrency bound.

The local evidence does not prove production capacity, latency, availability, high availability or disaster recovery.

## 18. Cost, supply chain and retained resources

No cloud or paid-model charge was incurred. Owner-accepted local CPU, disk, network and Docker usage occurred.

Accepted gaps and residual resources are:

- External reusable project virtual environment: retained.
- Disclosed immutable Qdrant and Python base images: retained.
- Shared BuildKit cache: retained for reusable build layers.
- BuildKit cache numeric size: **NOT RECORDED — OWNER-ACCEPTED EVIDENCE GAP**.
- Fully hashed transitive dependency lock: not created.
- Production SBOM attestation: not created.

The BuildKit residual risk is undisclosed local disk consumption and possible future eviction or recreation. Gyan Prakash Rai owns future measurement or removal through separately approved work.

## 19. Explicit NOT RUN and INDETERMINATE scope

The following remain **NOT RUN** where applicable:

- Live Bedrock or other external answer-model execution.
- Live OpenSearch and AWS integration.
- Production, Terraform or Kubernetes deployment.
- Paid evaluation services.
- Real Presidio and production PII-quality validation.
- Production identity integration and penetration testing.
- LLM answer generation and citation generation.
- Final Q5 safe-abstention validation.
- Production performance, high availability and disaster recovery.
- Application/source rollback and cloud rollback/teardown.
- Fully hashed transitive dependency-lock creation.

Remaining open **INDETERMINATE** activities: None. Historical INDETERMINATE evidence remains preserved with its later bounded rerun; the original result is not rewritten.

## 20. Decisions and alternatives

| Decision | Selected direction | Rejected or deferred alternative | Trade-off |
|---|---|---|---|
| Vector boundary | Provider-neutral `VectorStore` | Vendor SDK objects in business logic | Additional abstraction in exchange for portability and testability |
| Embeddings | Immutable offline MiniLM plus deterministic fake | Paid remote embedding as the default | Local resource use in exchange for privacy, repeatability and cost control |
| Vector database | Internal-only Qdrant | Host-published local port | More isolated integration topology with container-only access |
| PII handling | Inspect before embedding | Detect after vector creation | Earlier failure boundary prevents prohibited derived data |
| Authorization | Metadata filtering before provider search plus result validation | Model-decided or post-search-only authorization | More explicit filter contracts in exchange for fail-closed access control |
| Identity | Deterministic IDs and exact versions | Random IDs or ambiguous replacement | Strong idempotency and deletion semantics with stricter input contracts |
| Lifecycle | Separate rollback and teardown | Treat destroy as rollback | Clearer recovery and residue responsibilities |

## 21. Layman explanation

Think of Week 2 as a secure corporate library.

Before a document reaches a shelf, the librarian checks its identity, ownership, classification and privacy markings. The document is divided into labelled cards, and each card receives a numerical topic fingerprint. The cards are stored in a private room that is not open to the street.

When someone asks a question, the system creates a matching fingerprint but first checks the person's tenant, clearance, role and group. The librarian searches only the shelves that person may access and checks the returned cards again. Similarity helps find relevant cards, but it never grants permission. If a controlled change is wrong, the previous catalogue rules are restored; when the exercise ends, task-owned shelves and records are removed.

## 22. Thirty-second interview explanation

“Week 2 built a governed local retrieval layer. Approved documents are validated, privacy-checked, deterministically chunked and embedded with an immutable offline MiniLM model. A provider-neutral vector-store contract writes them to internal-only Qdrant. Queries carry tenant, clearance and ACL context, and the adapter filters before semantic search with result validation as defence in depth. We proved authorized top-five retrieval, isolation, rollback and teardown locally, while preserving that answer generation, citations, real Presidio and cloud deployment were not yet proved.”

## 23. Two-minute technical explanation

The ingestion pipeline validates provenance, tenant, classification and policy inputs before creating deterministic document and chunk identities. PII handling occurs before embedding so prohibited content cannot create derived vectors. Chunks use a 200-token maximum and 25-token overlap. Both chunks and questions use the approved 384-dimensional normalized MiniLM contract, loaded offline on CPU.

Business logic calls a provider-neutral `VectorStore`. Qdrant remains internal-only, and its adapter builds filters for tenant, clearance-permitted classifications, role/group ACL, PII status and ingestion status. The retrieval service validates active context and validates returned results again. Q1–Q4 proved expected authorized sources within the top five; Q5 did not prove safe abstention. A controlled State N+1 expectation regression was detected, removed and revalidated before task-owned resources were torn down separately.

## 24. Five interview questions and answer points

### 1. Why separate retrieval logic from Qdrant and OpenSearch SDKs?

Answer points: keep business rules provider-neutral; enable deterministic fake contracts; reduce migration impact; still require provider-specific evidence for filters, performance, security, cost and lifecycle.

### 2. Why must PII inspection happen before embedding?

Answer points: chunks, vectors and payloads are derived data; deleting only the source would not remove them; redact or quarantine must happen before the next irreversible representation; evidence must exclude protected content.

### 3. How is tenant isolation enforced during semantic search?

Answer points: active authorization context; tenant, clearance, role/group, PII and ingestion filters before provider search; result validation after search; missing context fails closed; similarity cannot authorize.

### 4. What did the top-five result prove, and what did it not prove?

Answer points: Q1–Q4 proved expected authorized source presence among five candidates; it did not prove final answer correctness, citation faithfulness, production quality or Q5 safe abstention.

### 5. What is the difference between rollback and teardown?

Answer points: rollback restores known-good State N after a detected regression; teardown removes scoped resources and verifies residue; destroying the environment is not recovery of the prior capability.

## 25. Practical architect scenario

A new provider returns semantically strong results but cannot reproduce the approved tenant/classification/ACL filter semantics. The correct response is to stop before enabling it, map every producer and consumer of the filter contract, obtain a bounded approval, implement negative isolation tests and produce new lifecycle evidence. Provider popularity or similarity quality cannot justify weakening authorization.

## 26. Owner teach-back record

- Owner: **Gyan Prakash Rai**
- Reviewer role: **Project Owner and Final Approval Reviewer**
- Teach-back date/timezone: **2026-08-25 23:59:08 SGT (UTC+08:00)**
- Teach-back decision: **PASS**
- Business explanation: **Confirmed** — the owner can explain the Week 2 business purpose and beneficiaries
- Architecture explanation: **Confirmed** — the owner can explain the document-to-vector-to-authorized-retrieval flow, Qdrant's internal-only role and the future OpenSearch boundary
- Decision and alternative explanation: **Confirmed** — the owner can explain deterministic identity, PII-before-embedding, chunking, immutable MiniLM, provider neutrality and metadata authorization
- Failure, rollback and teardown explanation: **Confirmed** — the owner can explain historical failure handling, consolidated remediation, State N restoration, teardown and residual-resource verification
- Interview-answer assessment: **PASS** — the owner confirmed at least three interview answers from this record
- Corrections requested by owner: **None**

The owner should be able to explain the business purpose, document-to-vector-to-authorized-retrieval flow, Qdrant's role, the PII and authorization boundaries, the State N rollback story and at least three interview answers without reading code.

## 27. Next-task handover

W2-13 is final-approved under the complete four-document Column N closure. The owner must reconcile the W2-13 tracker prompt/status cells and establish a clean committed baseline.

Before W3-001, the separately recorded W1-08 pre-commit and secret-scanning **OPEN CONTROL GAP** must also be resolved or explicitly reconciled through its governing owner decision. Week 3 may not infer that gap is closed merely because Week 1 tracker rows currently say Done.

Live Bedrock, OpenSearch/AWS, real Presidio, production deployment, answer generation, citations and safe abstention require separate approvals and new evidence.

## 28. Final Owner Approval

- Prompt/task ID: `WEEKLY-LEARN-001` / W2-13
- Reviewer exact name: **Gyan Prakash Rai**
- Reviewer role: **Project Owner and Final Approval Reviewer**
- Exact owner decision: **FINAL APPROVAL AFTER OWNER TEACH-BACK — APPROVED**
- Approval date and time/timezone: **2026-08-25 23:59:08 SGT (UTC+08:00)**
- Final status: **APPROVED FOR USER TRACKER UPDATE — W2-13**
- Documentation review status: **EXISTS, REVIEWED AND APPROVED; all four Column M manifest documents closed together**
- Owner teach-back status: **PASS**
- Owner-executed test status: **No new test or command applies to this learning-only task; approved Week 2 evidence is summarized without reclassification**
- Accepted warnings, risks, evidence gaps and limitations: All items recorded in this manifest are accepted, including local Linux/AMD64 scope, top-five/Q5 limitations, synthetic PII scope, dependency/SBOM gaps, live OpenSearch gap, retained local resources, unrecorded BuildKit numeric size and historical W2-001 reviewer/date gaps; no additional item is silently accepted
- NOT RUN and INDETERMINATE acceptance: All activities listed in section 19 remain **NOT RUN**; remaining open INDETERMINATE activities are None, while historical INDETERMINATE evidence remains preserved
- Deferred actions and responsible owner: Gyan Prakash Rai owns the W1-08 prerequisite, real Presidio, live OpenSearch/AWS, Week 3 generation/citation/abstention, production dependency locking, BuildKit measurement/removal, tracker reconciliation and clean-baseline establishment
- Deployment, rollback, teardown and residual-resource facts: W2-13 deployment was **NOT RUN**; approved Week 2 evidence is local-only; State N rollback and local task teardown passed; application/source/cloud rollback and cloud teardown remain **NOT RUN**; the external environment, disclosed shared base images and shared BuildKit cache remain accepted, with BuildKit numeric size not recorded
- Approval conditions and next-task handover: Preserve all historical classifications and the unchanged W2-11 architecture record; only the owner updates Excel and Git; W3-001 remains blocked until W1-08 is resolved or explicitly reconciled and a clean committed baseline exists
- Tracker update responsibility: **Owner — Gyan Prakash Rai**

## Column M approved document manifest

| Exact path | Classification | Purpose | Column N requirement |
|---|---|---|---|
| `docs/learning/W2-learning-review.md` | CREATE | Canonical W2-13 business, architecture and interview learning record | Closed — teach-back and Final Owner Approval recorded |
| `docs/deployment-records/W2-signoff.md` | UPDATE | Register the W2-13 learning handover without changing the prior W2-12 approval | Closed — final W2-13 handover reconciled |
| `docs/test-evidence/W2/W2-REVIEW-001.md` | UPDATE | Register the W2-13 downstream document and pending closure | Closed — downstream handover reconciled |
| `docs/test-evidence/README.md` | UPDATE | Index the canonical W2-13 learning record | Closed — final index state reconciled |

Column N closed all four documents together. The README update did not substitute for the learning record or either downstream handover document.
