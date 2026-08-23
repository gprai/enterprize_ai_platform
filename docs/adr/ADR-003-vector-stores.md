# ADR-003 — Vector-store boundary for local retrieval

- **Status:** Owner-approved for W2-001 implementation; Column N final task approval pending
- **Decision scope:** W2-001 local retrieval

## Business decision

Enterprise retrieval must be able to change storage technology without rewriting the business meaning of a document chunk, tenant boundary, authorization rule, or search result. W2-001 therefore uses a common vector-store contract and keeps vendor-specific client behavior behind adapters.

A **vector store** is a database optimized to search embeddings, which are numeric representations of content similarity.

## Architecture position

Application and orchestration code depend on the retrieval contract. The contract is implemented by:

- a deterministic fake for fast offline tests;
- Qdrant for the approved local integration test; and
- an OpenSearch adapter whose client boundary can be injected for offline testing.

The contract owns the stable behavior. Each adapter translates that behavior into its vendor client's calls without changing tenant, authorization, deterministic-ID, timeout, retry, exception, or return semantics.

## Decision

1. Preserve the owner-approved DATA-002, DATA-003, EMB-001, and SEC-001 contracts above vendor APIs.
2. Use stable, deterministic chunk identifiers so repeated processing of the same approved identity inputs addresses the same logical chunk.
3. Keep a deterministic fake as the always-available local contract implementation.
4. Use Qdrant for local integration only through the logical Compose network `qdrant_internal`.
5. Publish no Qdrant host port. Run the opt-in Qdrant contract from a profile-controlled, one-shot runner inside the internal network.
6. Keep OpenSearch behind an injected client boundary. Do not claim live AWS/OpenSearch verification from fake or injected-client tests.
7. Pin the runner base image to the approved immutable multi-platform index and record the approved Linux/AMD64 runtime manifest as an image label and automated contract.

## Alternatives considered

### Couple application code directly to one vendor

Rejected because vendor request shapes, failure modes, and lifecycle operations would spread into business code and make comparison or migration expensive.

### Publish Qdrant to the host while retaining an internal-only network

Rejected after owner-executed evidence showed a healthy container without an effective host endpoint in the selected Docker environment. More importantly, host publication was not required by the business use case.

### Add an outbound-capable network only to preserve host testing

Rejected for W2-001 because it would weaken the selected internal-only boundary. The owner preferred an in-network runner.

### Test only with a fake

Rejected as the sole strategy because a fake cannot prove that the real Qdrant client and server agree on collection creation, upsert, search, deletion, and cleanup behavior.

## Consequences and trade-offs

### Benefits

- Business contracts stay stable when a store changes.
- Fast fake tests and a real local integration test cover different failure classes.
- Internal-only Qdrant reduces accidental host exposure.
- The one-shot runner has no credentials, host port, persistent storage, Docker socket, or host-network access.
- Immutable image identity and Linux/AMD64 verification reduce ambiguity about the tested runtime.

### Costs and limitations

- Each adapter and its contract tests require maintenance.
- The in-network runner adds a Dockerfile, a narrow build context, dependencies, and local build time.
- Dependency-family bounds do not provide a fully locked transitive dependency graph.
- A local Qdrant PASS does not prove live OpenSearch compatibility, AWS permissions, production scaling, backups, disaster recovery, or data residency.
- The explicit Linux/AMD64 Dockerfile constraint produces a non-blocking BuildKit portability warning by design.

## Verification

- Static Qdrant lifecycle contract: **PASS**, 8 tests.
- Complete local suite: **PASS**, 157 passed, 1 expected skip, 3 deselected.
- MyPy and Ruff: **PASS**.
- Qdrant one-shot integration: **PASS**, 1 test.
- Host-port absence: **PASS** in both configured and effective Docker state.
- Collection deletion and absence assertion: **PASS** as part of the integration test.
- Project-labelled Docker residue after teardown: **PASS**, zero containers, volumes, networks, and built images.
- Live AWS/OpenSearch: **NOT RUN**.

## Failure and rollback

If a vendor adapter fails, callers retain one contract-level failure boundary rather than depending on vendor exception shapes. The Qdrant integration deletes its named test collection in `finally` and asserts absence. Owner-executed teardown successfully removed task-local runtime resources.

Source or configuration rollback was **NOT RUN**. A future change to remove or replace an adapter, runner, image, or Compose service requires a new owner-approved code boundary. Until then, the deterministic fake remains the offline testing path.

## Interview talking points

- Explain the difference between an interface contract and a vendor adapter.
- Explain why fake, injected-client, and real integration tests are complementary.
- Explain why immutable image identity matters even for local tests.
- Explain the security benefit and operational cost of an internal-only database.
- State precisely why local Qdrant evidence cannot be presented as live OpenSearch evidence.
