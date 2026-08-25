# Week 2 Local Retrieval Architecture and Owner Teach-Back

## 1. Purpose and business use case

The Week 2 local-retrieval capability turns approved enterprise documents into searchable, authorized evidence without depending on a paid model API or exposing the local vector database to the host network.

The business objective is not merely to find text with similar wording. It is to produce a repeatable and auditable retrieval process in which document identity, PII policy, tenant authorization, model identity, retrieval results, rollback and cleanup can all be explained and verified.

A regulated-enterprise example is an internal financial-services knowledge system. Two users may ask semantically identical questions, but they must receive different results when their tenant, role, group, classification or clearance differs. The model must never decide access by itself.

## 2. Week 2 end-to-end architecture

The approved local flow is:

```text
Approved document
  -> deterministic validation and identity
  -> PII inspection and redact-or-quarantine decision
  -> token-based chunking
  -> MiniLM embeddings
  -> authorized Qdrant storage
  -> question embedding
  -> metadata-filtered cosine-similarity search
  -> top-five permitted source results
  -> bounded rollback when required
  -> complete task-resource removal
```

The main trust boundaries are the document-ingestion boundary, the PII decision, the embedding-provider boundary, the vector-store adapter, the authorization filter and the evidence boundary. A failure at any boundary must stop before unauthorized or malformed data reaches the next component.

## 3. Component responsibilities

- **Document validation and identity:** validates required provenance, tenant and classification metadata and produces deterministic document identities.
- **PII policy:** examines content before derived data is created and chooses the approved redact or quarantine outcome.
- **Chunker:** splits normalized content into deterministic token-bounded pieces while preserving source and version identity.
- **Embedding provider:** converts chunks and questions into vectors under one model contract.
- **VectorStore contract:** keeps business logic independent of Qdrant or OpenSearch SDK objects.
- **Qdrant adapter:** implements the approved local vector-storage and search boundary and constructs the approved metadata filters.
- **Authorization context and filters:** restrict searches by tenant identity, classifications permitted by clearance, role/group access-control lists, PII status and ingestion status.
- **Retrieval service:** validates that the authorization context is active and structurally valid, embeds the question and delegates retrieval through the `VectorStore` boundary.
- **Rollback and teardown controls:** restore the known-good expectation after a controlled regression and remove task-owned resources separately.

## 4. Embeddings and the approved MiniLM contract

An embedding converts the semantic meaning of text into a numerical vector. The vector is not a readable answer; it is a representation used for comparison, clustering and search.

The approved model is `sentence-transformers/all-MiniLM-L6-v2` at immutable revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`. Its approved output contract is:

- 384 dimensions.
- Normalized vectors.
- Cosine-compatible similarity.
- CPU-only local execution.
- Offline loading from the explicitly approved external snapshot.
- No authentication token and no remote-code trust.

Document chunks and questions use the same model contract. A model, revision, dimension or normalization mismatch fails before a vector query or mutation.

## 5. Fake versus real embedding providers

`FakeEmbeddingProvider` produces deterministic vectors for fast, safe and repeatable automated tests. It proves interface behavior, dimensions, error handling and application control flow without loading or downloading a model.

The fake does not reproduce real semantic understanding and cannot prove retrieval quality. The real Sentence Transformer adapter performs actual local inference and separately proves immutable snapshot loading, offline operation, dimensions and normalization.

This separation keeps ordinary tests predictable while retaining a bounded real-model integration path. Passing fake-provider tests must never be reported as real semantic-quality evidence.

## 6. Cosine similarity

Cosine similarity compares vector direction rather than absolute magnitude. For vectors `A` and `B`, it is conceptually:

```text
cosine(A, B) = dot(A, B) / (length(A) * length(B))
```

Because the approved embeddings are normalized, comparison is consistent with the cosine contract used by the collection. A higher score generally means the question and chunk are semantically closer.

A high score does not prove that the chunk is factually correct, authorized, complete or sufficient for an answer. Similarity chooses candidates; validation and authorization decide whether they may be used.

## 7. Chunk size and overlap

The approved controlled baseline is:

- Maximum chunk size: **200 tokens**.
- Overlap: **25 tokens**.

Smaller chunks often improve precision because each vector represents a narrower idea, but they may lose surrounding context. Larger chunks preserve more context but can mix unrelated ideas, use more model input and reduce retrieval precision.

Overlap helps preserve meaning when a sentence or idea crosses a chunk boundary. Excessive overlap creates additional vectors, storage consumption and repeated retrieval results. The 200/25 choice is an initial governed baseline, not a universal optimum; future changes require retrieval-quality comparison and re-ingestion evidence.

## 8. Metadata and authorization filtering

Semantic similarity must never determine access. The active retrieval-authorization filters are:

- Tenant identity.
- Classifications permitted by the requester's clearance.
- Role and group access-control lists.
- PII status.
- Ingestion status.

Source identity and document version support provenance, deterministic identity, idempotent upsert, version-aware deletion and evidence traceability. They are not current query-authorization filters.

The retrieval service validates that the authorization context is active and structurally valid, then delegates retrieval through the vector-store boundary. The Qdrant adapter constructs and applies the approved metadata filters before vector search so the provider is not asked to return prohibited candidates. Returned-result validation provides defence in depth before results leave the retrieval boundary. Unauthorized contexts must receive zero protected chunks even when the question is semantically similar to restricted content.

This is a fail-closed design: missing or incompatible authorization context stops retrieval instead of broadening access.

## 9. PII-before-embedding design

PII inspection occurs before chunking, embedding and vector storage because chunks, embeddings and vector payloads are derived data. If sensitive content is embedded first, deleting only the original document does not remove every derived exposure.

Approved content is redacted or quarantined before vector creation. Quarantined content must not enter Qdrant or appear in retrieval results. Evidence must not contain raw corpus content, PII, credentials or secrets.

Week 2 used `SyntheticPiiAnalyzer` to prove the control path. Real Presidio execution and production PII-detection-quality validation were **NOT RUN**.

## 10. Qdrant internal-only architecture

Qdrant is the approved local vector-database foundation. It provides a real client/server environment for learning collection validation, ingestion, filtering, retrieval, rollback and teardown.

Qdrant is attached only to the logical Compose network `qdrant_internal`, which remains internal. It has no Windows host, LAN or public port publication. One-shot test runners access it through Docker service discovery at the internal service address.

The rejected `127.0.0.1:6333` requirement would have introduced an unnecessary host exposure. Internal service discovery preserves the isolation boundary while still allowing approved integration testing.

## 11. Qdrant-to-OpenSearch migration considerations

Business logic depends on the provider-neutral `VectorStore` contract rather than vendor SDK types. This supports a future OpenSearch adapter without rewriting document, authorization or retrieval-domain logic.

Migration is not automatic. A future OpenSearch implementation must revalidate:

- Vector dimensions and cosine behavior.
- Metadata-filter semantics and authorization isolation.
- Idempotent ingestion and deterministic identities.
- Timeouts, errors, retries and partial failures.
- Performance, scaling and operational support.
- Cloud access, residency, credentials and cost.
- Backup, rollback, teardown and residual-resource behavior.

Live OpenSearch and AWS integration were **NOT RUN** in Week 2.

## 12. Retrieval-quality results and limitations

The approved W2-004 evidence shows:

- Q1–Q4 returned the expected authorized source within the top five results.
- Stable ingestion did not create duplicate identities or point counts.
- Unauthorized contexts retrieved zero protected content.
- Quarantined content was absent.
- Q5 recorded retrieval behavior only.

Top-five retrieval is a recall-oriented retrieval measure. It does not prove final answer correctness. Week 2 did not prove that citations are complete, that an LLM-generated answer is faithful, or that the system safely abstains for Q5. Those capabilities remain deferred to Week 3 and later work.

## 13. Security, privacy, reliability and cost trade-offs

- **Security:** authorization precedes provider access, Qdrant remains internal-only and the runner uses bounded least-privilege controls.
- **Privacy:** PII policy precedes embedding; quarantine prevents prohibited derived vectors; evidence excludes raw protected content.
- **Reliability:** deterministic identities and idempotent ingestion reduce duplicates and support exact deletion. Contract mismatches fail before query or mutation.
- **Concurrency:** synchronous CPU inference is moved outside the asynchronous event loop and guarded by a process-wide lock so cancellation does not allow overlapping model work.
- **Cost:** no cloud or paid-model charge was incurred. Owner-accepted local CPU, disk, network and Docker consumption occurred.
- **Supply chain:** exact direct dependency versions were approved, but no fully hashed transitive dependency lock or production SBOM attestation was created.

Local Linux/AMD64 evidence does not prove production capacity, latency, availability, compliance, high availability or disaster recovery.

## 14. Failure detection and remediation approach

Week 2 retained its failure history rather than converting failures into PASS. Examples included a Docker build-context mismatch, a missing approved model-blob path, lint findings and the controlled retrieval-regression exercise.

The required response is:

1. Stop on FAIL or INDETERMINATE output.
2. Determine the complete root cause and affected producer-consumer surface read-only.
3. Request one bounded remediation approval.
4. Apply only the approved correction.
5. Re-run the owner-approved evidence sequence.
6. Preserve the historical failure and final result separately.

An evidence gap remains a learning gap; it is never filled with an invented result.

## 15. Rollback versus teardown

Rollback restores the last-known-good capability. Teardown removes scoped resources. Destroying an environment is therefore not rollback.

The W2-004 rollback proof used:

- **State N:** approved retrieval configuration and expectations.
- **State N+1:** a bounded, test-scoped and non-mutating expectation override.
- **Detection:** the regression check rejected the N+1 expectation.
- **Rollback:** removal of the override restored State N.
- **Verification:** health, idempotent ingestion, Q1–Q4 top-five behavior, authorization isolation and quarantine absence were revalidated.

Complete removal then deleted the task collection and derived vectors, Compose containers, task network, named volume, local runner image, task-owned temporary files and repository-generated residue.

## 16. Retained resources and evidence gaps

The external W2-002 model cache was removed during W2-004 teardown and verified absent.

The following reusable local resources remain with owner acceptance:

- External Python virtual environment.
- Disclosed immutable Qdrant and Python base images.
- Shared BuildKit cache used for reusable Docker build layers.

The BuildKit cache size is **NOT RECORDED — OWNER-ACCEPTED EVIDENCE GAP**. It is not an INDETERMINATE test result. The residual risk is undisclosed disk consumption and possible future cache eviction or recreation. Its measurement or removal is deferred to separately approved Docker-cleanliness or disk-governance work.

Other evidence gaps include the absence of real Presidio proof, a fully hashed transitive dependency lock, production SBOM attestation, generated-answer/citation evidence, production performance and cloud deployment evidence.

## 17. Owner teach-back record

- Prompt/task ID: `W2-LEARN-001`
- Reviewer: Gyan Prakash Rai
- Reviewer role: Project Owner, Learner and Approval Reviewer
- Teach-back decision: **PASS**
- Learning status: Week 2 learning objectives completed, subject to owner review of this created note
- Acceptance demonstrated: the owner can explain embeddings, cosine similarity, the 200/25 chunking baseline, metadata authorization, PII-before-embedding, internal-only Qdrant, the OpenSearch boundary, retrieval limitations, rollback and teardown
- Corrections captured: host-port exposure rejected; Docker service discovery retained; top-five distinguished from answer quality; Q5 distinguished from safe abstention; synthetic PII distinguished from real Presidio; rollback distinguished from teardown; BuildKit size gap distinguished from INDETERMINATE
- Tracker update responsibility: Owner

## 18. Five interview questions with answer points

### 1. Why use embeddings in enterprise retrieval?

Answer points: embeddings represent meaning numerically; the approved MiniLM contract produces normalized 384-dimensional vectors; document chunks and questions use the same contract; embeddings enable semantic comparison but are not answers.

### 2. How do chunk size and overlap affect quality and cost?

Answer points: smaller chunks improve precision but can lose context; larger chunks preserve context but may mix ideas; overlap preserves boundary meaning but increases vectors, storage and duplicate-result risk; 200/25 is an evidence-controlled baseline.

### 3. How is tenant isolation enforced?

Answer points: authorization context includes tenant, role, group, classification and clearance; filters constrain the search before the provider call; returned results are checked again; missing context fails closed; the model never decides access.

### 4. Why can Qdrant later be replaced by OpenSearch?

Answer points: provider-neutral contracts isolate vendor APIs; domain models and authorization rules remain stable; migration still requires new evidence for vector behavior, filters, performance, cloud security, cost, backup and teardown.

### 5. What is the difference between rollback and teardown?

Answer points: rollback restores State N after rejecting State N+1; teardown removes task-owned resources; the W2 proof used a non-mutating expectation override for regression and then separately removed the collection, containers, network, volume and runner image.

## 19. Remaining NOT RUN and deferred capabilities

The following remain **NOT RUN**:

- Live OpenSearch integration.
- AWS integration.
- Production deployment.
- Kubernetes or Terraform deployment.
- Paid model or API execution.
- Real Presidio execution and production PII-quality validation.
- Production-scale retrieval, high-availability and disaster-recovery testing.
- LLM answer generation.
- Citation generation.
- Final Q5 safe-abstention validation.
- Fully hashed transitive dependency-lock generation.

Remaining **INDETERMINATE** items: None. The historical W2-002 MyPy internal-tool INDETERMINATE was followed by a successful rerun and is not a remaining open activity.

Deferred work must remain open and must not be described as implemented.

## 20. Final Owner Approval

- Prompt/task ID: `W2-LEARN-001`
- Reviewer: Gyan Prakash Rai
- Reviewer role: Project Owner, Learner and Approval Reviewer
- Owner decision: **APPROVED**
- Approval timestamp: 2026-08-25 21:32:08 SGT (UTC+08:00)
- Final learning and documentation status: **APPROVED FOR USER TRACKER UPDATE — W2-LEARN-001**
- Code review status: Not applicable to this documentation-only learning task; no code, test, configuration, dependency or infrastructure path was changed.
- Documentation review status: The corrected one-document Column M manifest was reviewed and approved. The owner confirmed the active retrieval filters and the separate provenance and version-lifecycle responsibilities.
- Owner teach-back and test status: **PASS** for the Week 2 teach-back. W2-LEARN-001 ran no new test or command and relies only on the separately approved Week 2 evidence summarized in this note.
- Accepted warnings, risks, evidence gaps and limitations: local Week 2 evidence does not prove production or cloud deployment; Q1–Q4 prove expected-source presence within the top five; Q5 is retrieval-only and does not prove safe abstention; synthetic PII analysis does not prove production Presidio quality; direct dependencies lack a fully hashed transitive lock; live OpenSearch compatibility was not proved; the external virtual environment, disclosed shared Docker base images and shared BuildKit cache remain accepted; BuildKit cache size is not recorded and remains an owner-accepted evidence gap; historical cache-retention statements remain accurate for their task stages, and the W2-002 model cache was subsequently removed during approved W2-004 teardown.
- NOT RUN: live OpenSearch; AWS; production, Terraform or Kubernetes deployment; real Presidio; paid model or API execution; LLM answer generation; citation generation; final Q5 safe-abstention validation; production-scale performance, high-availability or disaster-recovery testing; fully hashed transitive-lock generation; Git mutation by Codex; and Excel modification by Codex.
- INDETERMINATE: None for W2-LEARN-001. Historical INDETERMINATE facts in other approved task evidence remain unchanged.
- Deployment, rollback and teardown: W2-LEARN-001 performed no deployment, created no runtime resource, and required no runtime rollback or teardown. W2-004 local rollback and teardown remain governed by their approved evidence; cloud rollback and teardown were **NOT RUN**.
- Residual resources: the external virtual environment is retained and accepted; disclosed shared Docker base images may remain; shared BuildKit cache is retained with its numeric size waived as an accepted evidence gap; approved W2-004 evidence records no prohibited project-labelled residue.
- Deferred actions and responsible owner: Gyan Prakash Rai owns later approved OpenSearch/AWS validation, separate real-Presidio validation, Week 3 generation/citation/safe-abstention work, production dependency locking, ADR-003/ADR-006/authorization-document reconciliation, separate `RAG-001` status reconciliation with intended status `In Progress`, and W2-11/W2-12 tracker reconciliation.
- Approval conditions: preserve the exact one-document manifest and corrected filter wording; preserve every approved result and limitation; change no other repository path; complete one-row reconciliation; keep `docs/deployment-records/W2-signoff.md` absent until W2-12; and permit only the owner to update the tracker.
- Next-task handover: later tasks may rely on the approved Week 2 local-retrieval architecture and teach-back, but may not infer production/cloud readiness, live OpenSearch/AWS, real Presidio quality, generated answers, citations, safe abstention or the other deferred capabilities.
- Tracker update responsibility: Owner
