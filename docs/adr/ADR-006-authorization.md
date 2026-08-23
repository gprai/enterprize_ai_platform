# ADR-006 — Authorization at the retrieval boundary

- **Status:** Owner-approved for W2-001 implementation; Column N final task approval pending
- **Decision scope:** SEC-001 retrieval authorization and tenant isolation

## Business decision

Retrieval must not return a relevant document chunk unless the requester is also allowed to receive it. Semantic similarity is never sufficient authorization.

W2-001 therefore treats authorization metadata and requester context as part of the retrieval contract rather than as optional user-interface filtering.

## Definitions

- **Authentication** establishes who the requester is. W2-001 receives that established identity as authorization context; it does not implement an identity provider.
- **Authorization** decides what that requester may do and which records they may receive.
- A **tenant** is an isolated customer or organizational data boundary.
- **Clearance** is the highest approved sensitivity the requester may access.
- A **role** grants a named type of operation, such as reading, ingestion, or administration.
- A **group** represents membership-based access to a record.
- **Fail closed** means uncertainty or a missing required condition results in denial, not access.

## Decision

1. Every protected operation receives an authorization context containing subject, tenant, roles, and clearance.
2. Every stored chunk carries the tenant and the classification and access metadata required by SEC-001.
3. Retrieval is limited to the requester's tenant before a result may be returned.
4. A result must not exceed the requester's approved classification clearance.
5. Record-level role or group rules must be satisfied in addition to tenant and classification rules.
6. Write, read, document-deletion, and administrative operations use their approved operation-specific role gates.
7. Fake, Qdrant, and OpenSearch adapters must preserve the same authorization outcome even though their query and client mechanisms differ.
8. Missing or invalid authorization inputs and cross-tenant requests fail closed.

## Why enforcement belongs here

If filtering occurs only in a screen or after retrieval, an unauthorized record may already have reached application memory, logs, prompts, or model context. Enforcing the boundary before results are returned reduces that exposure and keeps behavior consistent across callers.

The vector store is still not the whole security system. Production identity validation, network controls, encryption, audit retention, secrets management, and cloud policy remain separate architecture responsibilities.

## Trade-offs

- More metadata and filter logic increase adapter and test complexity.
- Deny-by-default behavior can reduce availability when authorization data is incomplete, but this is preferred to silent disclosure.
- Adapter parity must be tested because different stores express filters differently.
- Group and role changes may require re-evaluation at request time; stored metadata alone must not be treated as a complete identity system.

## Verification

- Tenant-isolation security tests: **PASS**, 4 tests.
- Vector-store contract tests: **PASS**, 4 tests.
- Qdrant internal round trip: **PASS**, including authorized ingestion, retrieval, document deletion, and collection cleanup.
- Complete suite: **PASS**, 157 passed, 1 expected skip, 3 deselected.
- Live identity provider, live AWS IAM, and live OpenSearch authorization: **NOT RUN**.
- Production penetration testing and compliance certification: **NOT RUN**.

## Failure and rollback

The safe failure is no result or a denied operation. Authorization checks must not silently retry with weaker filters or a broader tenant scope.

No application rollback was executed for W2-001. Reverting or weakening the authorization contract would require a new owner decision and code approval. Local Qdrant teardown passed and left no project-labelled runtime resource.

## Layman explanation

Finding the right page and being allowed to read the page are two separate questions. W2-001 answers both. It first checks that the page belongs to the requester's organization and that the requester has sufficient sensitivity clearance and an allowed role or group. Only then may the page be returned.

## Interview talking points

- Distinguish authentication from authorization.
- Explain why tenant filtering is a security boundary, not a convenience filter.
- Explain defense in depth between application authorization and database query filters.
- Explain why authorization must happen before content enters a model prompt.
- Explain fail-closed behavior and its security-versus-availability trade-off.
