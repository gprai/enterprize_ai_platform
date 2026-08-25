# Retrieval authorization architecture

## Business purpose

The authorization architecture prevents relevant but unauthorized enterprise information from being returned to a requester or placed into an AI model's context.

## Where the control sits

W2-001 receives an established requester identity as an authorization context. The retrieval layer applies that context consistently across its fake, Qdrant, and OpenSearch adapter boundaries. Identity-provider login and token validation remain outside this task.

## End-to-end decision flow

1. The caller supplies the authenticated subject, tenant, roles, groups where applicable, and classification clearance.
2. `RetrievalService` validates that the authorization context is active and structurally valid and builds the provider-neutral retrieval policy.
3. `RetrievalService` embeds the approved query and delegates retrieval through the `VectorStore` boundary.
4. The selected adapter constructs its provider-specific filters from the approved policy.
5. Qdrant restricts candidates by tenant, classifications permitted by clearance, role/group access-control lists, PII status and ingestion status.
6. Similarity ranking operates only within that authorized candidate set.
7. Returned-result validation provides defence in depth before an adapter returns chunks across the retrieval boundary.
8. Administrative deletion uses its separately approved operation gate and remains tenant-scoped.

This ordering matters: filtering after content is returned could expose unauthorized text to memory, logs, prompts, or downstream services.

Source identity and document version support provenance, deterministic identity, idempotent upsert, version-aware deletion and evidence traceability. They are lifecycle fields, not current query-authorization filters. Semantic similarity cannot override any authorization decision.

## Adapter responsibilities

- The deterministic fake must reproduce the contract's allow and deny decisions for offline tests.
- Qdrant must translate the provider-neutral policy into tenant, clearance-permitted classification, role/group ACL, PII-status and ingestion-status filters while remaining internal-only in local testing. It must also reject any returned result that fails the approved authorization revalidation.
- OpenSearch must preserve the same contract through its client request boundary. Injected-client tests do not prove live AWS policy or service configuration.
- No adapter may silently broaden a tenant, classification, role, or group condition when it retries or handles a backend error.

## Security boundaries not completed by W2-001

The retrieval authorization contract does not replace:

- authentication and token validation;
- network identity and service-to-service policy;
- encryption and key management;
- secrets storage and rotation;
- production audit logging and monitoring;
- AWS IAM or OpenSearch domain policy; or
- privacy, retention, residency, and compliance approval.

## Evidence status

- Tenant-isolation tests: **PASS**, 4 tests.
- Vector-store contract tests: **PASS**, 4 tests.
- Qdrant authorized round trip and cleanup: **PASS**, 1 integration test.
- Complete local suite: **PASS**, 157 passed, 1 expected skip, 3 deselected.
- Live AWS/OpenSearch authorization, identity-provider integration, and production policy validation: **NOT RUN**.

## Failure story

The safe result of missing identity, wrong tenant, insufficient clearance, or an unapproved role or group is denial. The system must not fall back to an unfiltered search. Backend failure must remain a retrieval failure rather than becoming broader access.

## Layman explanation

The search engine first limits the filing cabinet to the requester's organization and permission level. It then searches for the best match inside that permitted cabinet. It never searches everything and hides forbidden pages afterward.

## Interview preparation

- Describe authorization before ranking and why order matters.
- Explain tenant isolation and fail-closed behavior.
- Explain the difference between contract tests and live cloud-policy tests.
- Describe how the same security meaning can be preserved across different databases.
