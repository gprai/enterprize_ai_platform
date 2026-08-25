# ADR-004 — Provider-neutral LLM boundary with Amazon Bedrock Runtime

- **Status:** Final — Approved
- **Decision ID:** ADR-004
- **Decision scope:** W3-001 provider-neutral LLM and cited-RAG foundation
- **Decision owner:** Gyan Prakash Rai
- **Content-task date:** 2026-08-26
- **Final approval reviewer:** Gyan Prakash Rai — Project Owner and Architecture Reviewer
- **Final approval timestamp:** 2026-08-26 00:55:10 Asia/Singapore (UTC+08:00)
- **Implementation authority:** None; this document does not authorize W3-001 code edits or live AWS activity

## Business decision

The platform needs evidence-bound answers without coupling retrieval and RAG business logic to one model provider's request, response or exception formats. A provider-neutral LLM boundary keeps ordinary development deterministic and offline while preserving an owner-gated path to Amazon Bedrock Runtime.

`FakeLLMProvider` is the default local and automated-test provider. Amazon Bedrock Runtime is the approved primary AWS LLM adapter through its `Converse` API, subject to separate owner approval for every live test and all account, model, privacy, residency, quota and cost inputs.

The owner has final-approved this ADR as the governing architecture decision for the W3-001 provider-neutral LLM and Amazon Bedrock boundary. This architecture approval does not authorize W3-001 implementation or prove any runtime behavior.

## Architecture boundary

The provider-neutral flow is:

```text
Authorized query
    -> authorization-aware retrieval
    -> qualifying evidence
    -> bounded, versioned prompt
    -> LLMProvider
        -> FakeLLMProvider by default
        -> BedrockLLMProvider only when explicitly configured
    -> structured provider response
    -> citation validation against supplied evidence
    -> cited answer or safe abstention
```

The `LLMProvider` contract owns provider-neutral chat requests, tool schemas, tool calls, tool results, token usage, nullable cost metadata, structured responses and normalized provider failures. Vendor SDK request dictionaries, response objects and exceptions must not escape the Bedrock adapter.

Retrieval authorization remains governed by ADR-006. Identity and query input remain separate. Authorization is enforced before retrieval results can enter a prompt, and semantic relevance never grants access.

## Provider decisions

### Fake provider

- `FakeLLMProvider` is the ordinary and default provider for local development, unit tests, contract tests, feature tests and security tests.
- Fake-only operation permits blank `LLM_MODEL_ID` and blank `AWS_REGION`.
- Fake mode must not initialize an AWS client, inspect credentials, connect to a network or incur a paid-service charge.
- Fake responses and failures are deterministic and injectable; retry tests use injected clocks, sleepers and failures and never wait for real retry durations.

### Amazon Bedrock Runtime

- The adapter uses Amazon Bedrock Runtime `Converse` only.
- There is no `invoke_model` fallback.
- The Bedrock client is injected for tests and created lazily for configured live use.
- Importing a module, constructing ordinary fake-mode settings or running the ordinary automated suite must perform no AWS activity.
- Selecting Bedrock with missing or invalid configuration fails closed before client creation.
- Selecting Bedrock never silently falls back to another provider, model, region or the fake provider.

## Owner authority and live-test gate

No live Bedrock execution is approved by this ADR. Live Bedrock remains **NOT RUN** until a separate TEST-001 approval records all of the following:

- exact AWS account;
- exact AWS region;
- exact Bedrock model ID or approved inference profile;
- approved short-lived IAM role or credential-chain boundary;
- model-access state;
- quota and throttling limits;
- privacy and data-residency decision;
- prompt and response logging policy;
- exact synthetic test inputs;
- expected token volume and maximum spend;
- rollback, credential-revocation and residual-resource expectations.

The least-privilege inference permission is limited to the approved model resource and the Bedrock action required by `Converse`. Credentials and secret values must never be stored in source, configuration examples, prompts, evidence or this ADR.

## Deadlines, retries, concurrency and cancellation

The provisional W3-001 provider limits are:

| Control | Required value |
|---|---:|
| Connect timeout | 3 seconds |
| Read timeout | 20 seconds |
| Outer provider-operation deadline | 30 seconds |
| Total application attempts | 2 |
| Retry jitter | Injected deterministic value from 100 to 250 milliseconds |
| Maximum concurrent provider calls | 4 process-wide |

The Bedrock adapter is the single retry-policy owner. SDK retries are disabled beyond the initial SDK attempt so SDK and application retries cannot multiply. Only explicitly classified throttling and transient availability or transport failures are retryable. Authentication, authorization, configuration, schema, policy, citation and validation failures are not retried.

The outer deadline includes provider-gate waiting and provider work. No later attempt may begin after that deadline. Cancellation propagates and prevents new attempts. A synchronous SDK request already running outside the async event loop may not be interruptible by Python; its connect/read timeout remains the bounding control, its late result is discarded, and it may still have consumed tokens. This residual risk must remain visible in live-test approval.

The concurrency limit is shared across provider instances in the process rather than being recreated per object. Tests must prove that multiple provider objects cannot exceed the same four-call boundary.

## Structured output, citations and tools

The final cited answer uses the one shared citation model. Every citation requires:

- `source_id`;
- `document_id`;
- `document_version`;
- `chunk_id`.

Every citation is validated against the exact qualifying authorized evidence supplied to the provider. Missing provenance, malformed output, duplicate or unsupported citation identities and fabricated citations fail closed. Provider-supplied identifiers do not grant access and are not trusted merely because they parse.

Retrieved text is delimited as untrusted data. It cannot override system policy. Context and output limits are enforced before provider invocation, and only qualifying evidence may enter the prompt.

Tool specification, tool call and tool result types are schema capability only in W3-001. W3-001 introduces no tool execution, approval loop or agent workflow. A cited-RAG response containing an unexpected tool call fails closed rather than silently executing or accepting it.

No provider-neutral or public model contains a chain-of-thought or reasoning field. Bedrock reasoning content, raw SDK responses and internal reasoning must not be returned, logged or written to evidence.

## Failure, fallback and abstention policy

- Authentication or authorization denial produces a stable normalized denial and must not retrieve or invoke the LLM.
- Weak evidence abstains before provider invocation.
- Mixed or conflicting document versions abstain or return an explicitly governed conflict result.
- Unauthorized evidence never enters provider context.
- Invalid structured output and unsupported or fabricated citations fail closed.
- Provider timeout, throttling and unavailability produce normalized operational errors.
- Normalized errors contain no endpoint, credential, raw prompt, raw context, raw answer, SDK exception text or reasoning.
- There is no automatic provider, model, region or fake fallback.
- Abstention represents insufficient or unusable evidence; it must not misrepresent an infrastructure or authorization failure as a knowledge result.

## Privacy, residency, logging and telemetry

Fake-provider execution transfers no data outside the process. Future Bedrock execution would send the approved question and authorized evidence to the owner-selected AWS region, so live use requires an explicit privacy, residency, retention and logging decision.

Application logs and evidence must exclude raw prompts, document text, answers, PII, credentials, AWS response objects and chain-of-thought. Safe operational fields may include provider name, model identifier after approval, prompt-policy version, outcome class, attempt count, bounded latency, token counts and nullable cost metadata. Model-specific cost remains unknown until the owner approves a model, region and price basis.

## Cost and quota controls

Ordinary fake and injected-client tests have no Bedrock charge. They may consume local CPU, memory and disk only.

No live compatibility, latency, quality, security, residency, quota or cost claim is permitted before owner-executed TEST-001 evidence. A future live test requires a maximum token budget and spend ceiling. The adapter records available token usage but does not invent a cost when approved pricing is unavailable.

## Verification boundary

W3-001 automated coverage must include provider-contract behavior, fake determinism, configuration validation, lazy client creation, no import-time AWS activity, structured parsing, citation traceability, weak/conflicting evidence, authorization short-circuit, deadlines, retry exhaustion, cancellation, process-wide concurrency, sensitive-data redaction and unexpected-tool rejection.

Bedrock unit tests use an injected stub client. Any live integration test is marked both `aws` and `paid`, remains excluded from the ordinary suite and is executed only through a separately approved TEST-001 sequence.

Creating this ADR runs no test and supplies no implementation or runtime evidence.

## Alternatives considered

### Couple RAG directly to boto3 response objects

Rejected because vendor request, response and exception shapes would spread into business logic, tests and future API contracts.

### Use Bedrock as the ordinary test provider

Rejected because it would introduce network, credential, quota, privacy, residency, nondeterminism and cost dependencies into normal verification.

### Automatically fall back to fake or another model

Rejected because an apparent success could conceal provider failure, alter quality or residency, and invalidate operational evidence.

### Expose model reasoning for diagnostics

Rejected because chain-of-thought is not part of the business contract and would add privacy, security and provider-portability risk.

## Consequences and trade-offs

Benefits include provider portability, deterministic local verification, explicit cloud gates, stable failures and auditable citation validation. Costs include adapter and normalization code, stricter schema handling, a shared concurrency boundary and separate live-provider evidence.

The fake proves contract behavior but not live Bedrock compatibility. An injected Bedrock client proves request and response mapping but not IAM, model access, quota, latency, quality, residency or billing behavior.

## Rollback, teardown and residual resources

Operational rollback selects the explicitly configured fake provider or disables the cited-RAG caller while preserving the approved Week 2 retrieval boundary. A runtime Bedrock failure never triggers automatic fallback. Restoring an earlier prompt, model or policy version requires a separately approved configuration change.

Ordinary W3-001 tests create no cloud resource, model cache, container, vector collection, registry artifact or deployment. Runtime teardown is therefore not applicable to the ordinary suite. Cache-safe commands and cleanliness tests must verify that no repository bytecode, pytest, Ruff, MyPy, environment, generated evidence or AWS/model artifact remains.

A future `Converse` call does not itself authorize creation of persistent infrastructure. Any temporary credential or session follows the owner-approved revocation and expiry boundary. Provider-side invocation logs, if enabled by a later owner decision, require separate retention and deletion handling.

The external reusable Python environment may remain as an owner-accepted local resource. No other W3-001 residue is accepted without an explicit owner decision.

## Final Owner Approval

- **Document:** `docs/adr/ADR-004-bedrock.md`
- **Reviewer:** Gyan Prakash Rai
- **Role:** Project Owner and Architecture Reviewer
- **Decision:** **APPROVED**
- **Approval date, time and timezone:** **2026-08-26 00:55:10 Asia/Singapore (UTC+08:00)**
- **Approved status:** **Final**
- **Governing decision:** ADR-004 is approved as the governing architecture decision for the W3-001 provider-neutral LLM and Amazon Bedrock boundary.

### Approved scope

The owner approval covers:

- provider-neutral LLM architecture;
- `FakeLLMProvider` as the ordinary local and automated-test provider;
- Amazon Bedrock Runtime `Converse` API as the approved Bedrock interface;
- injected and lazily created Bedrock clients;
- no AWS activity during import or ordinary tests;
- separate TEST-001 approval for live Bedrock access;
- explicit model, region, account, IAM, quota, privacy, residency and cost decisions before live execution;
- bounded timeouts, retries, concurrency and cancellation;
- no automatic provider, model, region or fake fallback;
- safe abstention and normalized failure handling;
- structured responses and citation validation;
- tool-schema support without tool execution or an agent loop in W3-001;
- no chain-of-thought exposure; and
- rollback, teardown and residual-resource boundaries.

### Accepted warnings, risks, evidence gaps and limitations

- ADR-004 is an architecture decision, not proof of implementation.
- W3-001 application code has not been implemented.
- Live Amazon Bedrock compatibility has not been demonstrated.
- Model quality, latency, quotas and production cost have not been measured.
- Provider privacy and data-residency compliance remain dependent on the later exact AWS region, account and model selection.
- The provisional RAG threshold of `0.50` demonstrates controlled behavior only and must be recalibrated through W3 evaluation.
- No production-readiness claim is approved.

### Confirmed NOT RUN

- W3-001 code implementation.
- Unit, contract, integration, feature, security, rollback and teardown tests for W3-001.
- AWS authentication or authorization.
- Bedrock model-access verification.
- Live Bedrock inference.
- Provider quota verification.
- Live latency, quality or cost evaluation.
- Deployment, rollback or cloud teardown.
- W1-08 pre-commit and secret-scanning implementation or testing.

### Confirmed INDETERMINATE

None, except matters explicitly classified as **NOT RUN** above.

### Deferred actions and responsible owners

- W3-001 implementation and owner-led testing: Project Owner under the W3-001 workflow.
- Exact AWS account, region, model ID, IAM role, quota and budget: Project Owner before live TEST-001.
- Privacy and data-residency approval: Project Owner before live TEST-001.
- RAG-threshold recalibration: W3 evaluation task.
- Production deployment approval: future separately controlled deployment task.
- W1-08: remains an owner-accepted, non-blocking deferral.

### Lifecycle and residual-resource facts

- Deployment: **NOT RUN**.
- Rollback: **NOT RUN** and not required for this documentation-only closure.
- Teardown: **NOT RUN** and not required.
- AWS or cloud resources created: None.
- Services, containers or models started: None.
- Credentials created or used: None.
- Platform cost: USD 0.
- Residual runtime resources: None.
- Residual documentation resource: this final-approved ADR-004 file.

### Approval conditions and handover

- ADR-004 approval does not authorize W3-001 code editing.
- W3-001 requires a newly regenerated, baseline-specific Column L manifest.
- Live Bedrock access requires a separate TEST-001 approval.
- Codex must not stage, commit or push.
- The owner must commit ADR-004 and the tracker correction, provide the resulting full 40-character SHA and confirm a clean working tree.
- Tracker and Git responsibility: **Owner — Gyan Prakash Rai**.
