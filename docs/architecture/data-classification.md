# Data classification in retrieval

## Business purpose

Data classification tells the platform how sensitive a document chunk is and which handling rules must follow it. Retrieval relevance must never override this label.

For W2-001, classification is carried with each chunk so that authorization decisions can be made at retrieval time and the result can remain traceable to its document, owner, integrity state, and ingestion state.

## Architecture position

The classification label enters the approved chunk contract during ingestion and travels through the vector-store abstraction into each adapter. At query time, the requester's tenant, clearance, roles, and groups are compared with the stored metadata before a result may be returned.

An **embedding** is a numeric representation used for similarity search. It does not replace the original text's classification. The embedding and its metadata must be protected as part of the classified record.

## Required control concepts

- **Tenant identity:** identifies the isolated customer or organizational boundary.
- **Classification:** expresses the sensitivity of the chunk.
- **Clearance:** expresses the maximum classification the requester may access.
- **Allowed roles and groups:** provide record-level access conditions.
- **Data owner:** identifies the accountable business owner.
- **Content hash:** supports integrity and deterministic identity decisions.
- **PII status:** records the approved state of personally identifiable information handling.
- **Ingestion status:** records whether the chunk is in an approved lifecycle state for retrieval.
- **Document identity and version:** preserve provenance when source content changes.

## Decision flow

1. Establish the requester's authorization context outside the vector store.
2. Reject a request that lacks required identity or authorization information.
3. Restrict candidates to the requester's tenant.
4. Reject candidates above the requester's classification clearance.
5. Apply the approved role and group conditions.
6. Return only authorized results while preserving document and chunk provenance.

## Privacy and operational rules

- Do not place credentials, unrestricted source content, or sensitive prompts in test evidence.
- Synthetic local test data does not prove controls for real sensitive data.
- Production encryption, key ownership, data residency, backup, retention, deletion, and audit requirements need environment-specific approval and evidence.
- A change in classification or authorization metadata must not be handled only by changing the user interface; stored and indexed enforcement state must remain consistent.

## W2-001 evidence boundary

- Model, vector-contract, tenant-isolation, and complete-suite checks: **PASS**.
- Qdrant used synthetic content on an internal-only local network: **PASS**.
- Live sensitive-data ingestion, privacy review, residency verification, and production retention/deletion validation: **NOT RUN**.

## Failure and remediation

Missing, invalid, or inconsistent classification information must fail closed. Operators should quarantine or reject the affected ingestion rather than silently assign a less restrictive label. Any reclassification or production re-indexing procedure is outside W2-001 and requires separate approval, audit evidence, and rollback planning.

## Layman explanation

The similarity fingerprint helps find a page, while the classification label controls whether the page may be shown. Keeping both together prevents the search system from treating a highly relevant but restricted page as safe merely because it matches the question.

## Interview preparation

- Explain why embeddings inherit the protection needs of their source content.
- Explain the difference between classification, clearance, role, and group.
- Explain how document version and content hash support traceability.
- Explain why local synthetic-data tests do not establish production compliance.
