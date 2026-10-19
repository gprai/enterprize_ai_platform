"""Read-only validation of the approved repository contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .lifecycle_models import ControlMatrixRow, ProductionReadinessReference

from .contracts import ContractError
from .lifecycle_io import load_lifecycle_config
from .lifecycle_models import OPERATIONAL_SCHEMA_VERSION
from .live_validation import W6004Error, validate_source_contract

EXPECTED_SCHEMA_VERSION = "1.0"
EXPECTED_PROJECT = {
    "name": "enterprise-ai-platform",
    "owner": "Gyan Prakash Rai",
    "default_environment": "sandbox",
    "cost_center": "ai_platform_learn",
    "repository": "https://github.com/gprai/enterprize_ai_platform",
    "expires_at": "31/12/2026",
}
PERMITTED_STATUSES = (
    "Not Started",
    "In Progress",
    "Blocked",
    "Ready for Review",
    "Done",
    "Deferred",
)
EXPECTED_W6_003_IMPLEMENTATION_PATHS = (
    "configs/readiness/local-integrated-readiness.yaml",
    "tools/w6_003_readiness.py",
    "tests/fakes/readiness.py",
    "tests/unit/test_w6_003_readiness.py",
    "tests/contract/test_w6_003_readiness_contract.py",
    "tests/integration/test_w6_003_platform_composition.py",
    "tests/feature/test_w6_003_integrated_readiness.py",
    "tests/smoke/test_w6_003_local_smoke.py",
    "tests/security/test_w6_003_readiness_security.py",
    "tests/rollback/test_w6_003_local_rollback.py",
    "tests/teardown/test_w6_003_readiness_cleanliness.py",
    "Makefile",
    "pyproject.toml",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/integration/test_dependency_contract.py",
    ".github/workflows/ci.yml",
    "tests/integration/test_w5_002_ci_composition.py",
)
EXPECTED_FEATURE = {
    "id": "MVP-001",
    "implementation_paths": list(EXPECTED_W6_003_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W1-03", "W1-04", "W1-07"],
}
EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS = (
    "docker-compose.yml",
    "docker/qdrant-test-runner.Dockerfile",
    "docker/qdrant-test-runner.Dockerfile.dockerignore",
    "docker/qdrant-test-runner.requirements.txt",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/authorization.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/models.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/retrieval/adapters/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "tests/unit/test_models.py",
    "tests/contract/test_vector_store.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_qdrant.py",
    "tests/feature/test_w2_001_retrieval_contract.py",
    "tests/security/test_tenant_isolation.py",
    "tests/teardown/test_w2_001_qdrant_lifecycle.py",
    "src/enterprise_ai_platform/embeddings/__init__.py",
    "src/enterprise_ai_platform/embeddings/base.py",
    "src/enterprise_ai_platform/embeddings/errors.py",
    "src/enterprise_ai_platform/embeddings/fake.py",
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py",
    "tests/unit/test_embedder.py",
    "tests/contract/test_embedder.py",
    "tests/integration/test_sentence_transformer_embedder.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/security/test_embedder_security.py",
    "tests/teardown/test_w2_002_embedder_cleanliness.py",
    "requirements.txt",
    "configs/pii-policy.yaml",
    "configs/eval/w2-starter.jsonl",
    "data/sample/corpus-manifest.json",
    "data/sample/approved/source-of-truth-v1.1.md",
    "data/sample/approved/coaching-blueprint.md",
    "data/sample/restricted-fixtures/restricted-test.txt",
    "src/enterprise_ai_platform/ingestion/__init__.py",
    "src/enterprise_ai_platform/ingestion/errors.py",
    "src/enterprise_ai_platform/ingestion/models.py",
    "src/enterprise_ai_platform/ingestion/identity.py",
    "src/enterprise_ai_platform/ingestion/normalization.py",
    "src/enterprise_ai_platform/ingestion/loaders.py",
    "src/enterprise_ai_platform/ingestion/pii.py",
    "src/enterprise_ai_platform/ingestion/tokenizer.py",
    "src/enterprise_ai_platform/ingestion/chunking.py",
    "src/enterprise_ai_platform/ingestion/pipeline.py",
    "tests/unit/test_chunking.py",
    "tests/unit/test_ingestion.py",
    "tests/contract/test_ingestion_manifest.py",
    "tests/contract/test_pii_policy.py",
    "tests/integration/test_ingestion_pdf.py",
    "tests/integration/test_ingestion_tokenizer.py",
    "tests/integration/test_dependency_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "tests/security/test_pii.py",
    "tests/security/test_ingestion_paths.py",
    "tests/smoke/test_ingestion_cli.py",
    "tests/rollback/test_w2_003_ingestion_rollback.py",
    "tests/teardown/test_w2_003_ingestion_cleanliness.py",
    "docker-compose.w2-004.yml",
    "docker/local-retrieval-runner.Dockerfile",
    "docker/local-retrieval-runner.Dockerfile.dockerignore",
    "docker/local-retrieval-runner.requirements.txt",
    "Makefile",
    "src/enterprise_ai_platform/retrieval/service.py",
    "tools/verify_w2_004_local.py",
    "tests/unit/test_retrieval_service.py",
    "tests/unit/test_verify_w2_004_local.py",
    "tests/contract/test_retrieval_service.py",
    "tests/feature/test_local_retrieval.py",
    "tests/security/test_w2_004_retrieval_security.py",
    "tests/rollback/test_w2_004_local_rollback.py",
    "tests/teardown/test_w2_004_retrieval_cleanliness.py",
    "configs/rag.yaml",
    ".env.example",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/json_contracts.py",
    "src/enterprise_ai_platform/llm/__init__.py",
    "src/enterprise_ai_platform/llm/errors.py",
    "src/enterprise_ai_platform/llm/models.py",
    "src/enterprise_ai_platform/llm/provider.py",
    "src/enterprise_ai_platform/llm/fake.py",
    "src/enterprise_ai_platform/llm/bedrock.py",
    "src/enterprise_ai_platform/llm/factory.py",
    "src/enterprise_ai_platform/rag/__init__.py",
    "src/enterprise_ai_platform/rag/config.py",
    "src/enterprise_ai_platform/rag/errors.py",
    "src/enterprise_ai_platform/rag/models.py",
    "src/enterprise_ai_platform/rag/prompt.py",
    "src/enterprise_ai_platform/rag/service.py",
    "tests/unit/test_config.py",
    "tests/unit/test_llm_provider.py",
    "tests/unit/test_bedrock_adapter.py",
    "tests/unit/test_prompt_template.py",
    "tests/unit/test_rag_pipeline.py",
    "tests/contract/test_llm_provider.py",
    "tests/contract/test_rag_config.py",
    "tests/contract/test_rag_result.py",
    "tests/integration/test_bedrock.py",
    "tests/feature/test_w3_001_cited_rag.py",
    "tests/security/test_configuration_security.py",
    "tests/security/test_w3_001_cited_rag_security.py",
    "tests/rollback/test_w3_001_rag_rollback.py",
    "tests/teardown/test_w3_001_rag_cleanliness.py",
)
EXPECTED_W3_003_EDITABLE_PATHS = (
    "src/enterprise_ai_platform/guardrails/__init__.py",
    "src/enterprise_ai_platform/guardrails/adapter.py",
    "src/enterprise_ai_platform/guardrails/errors.py",
    "src/enterprise_ai_platform/guardrails/models.py",
    "src/enterprise_ai_platform/guardrails/policy.py",
    "tests/unit/test_guardrails.py",
    "tests/contract/test_guardrail_contract.py",
    "tests/integration/test_guardrail_composition.py",
    "tests/feature/test_w3_003_guardrails.py",
    "tests/security/test_w3_003_guardrails_security.py",
    "tests/rollback/test_w3_003_guardrails_rollback.py",
    "tests/teardown/test_w3_003_guardrails_cleanliness.py",
    "src/enterprise_ai_platform/rag/service.py",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/unit/test_rag_pipeline.py",
    "tests/security/test_w3_001_cited_rag_security.py",
    "tests/teardown/test_w3_002_evaluation_cleanliness.py",
)
_W3_003_EDITABLE_PATH_SET = frozenset(EXPECTED_W3_003_EDITABLE_PATHS)
EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS = (
    tuple(
        path
        for path in EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS
        if path not in _W3_003_EDITABLE_PATH_SET
    )
    + EXPECTED_W3_003_EDITABLE_PATHS
)
EXPECTED_W3_004_EDITABLE_PATHS = (
    "configs/rag/versions/known-good-v2.json",
    "configs/rag/versions/synthetic-regression-v2.json",
    "src/enterprise_ai_platform/rag_rollback/__init__.py",
    "src/enterprise_ai_platform/rag_rollback/errors.py",
    "src/enterprise_ai_platform/rag_rollback/models.py",
    "src/enterprise_ai_platform/rag_rollback/identity.py",
    "src/enterprise_ai_platform/rag_rollback/state.py",
    "src/enterprise_ai_platform/rag_rollback/service.py",
    "tools/ragrollbackctl.py",
    "tests/unit/test_rag_rollback_identity.py",
    "tests/unit/test_rag_rollback_state.py",
    "tests/contract/test_rag_rollback_contract.py",
    "tests/integration/test_rag_rollback_composition.py",
    "tests/feature/test_w3_004_rag_rollback.py",
    "tests/security/test_w3_004_rag_rollback_security.py",
    "tests/rollback/test_w3_004_rag_rollback.py",
    "tests/teardown/test_w3_004_rag_rollback_cleanliness.py",
    ".gitignore",
    "src/enterprise_ai_platform/rag/prompt.py",
    "src/enterprise_ai_platform/evaluation/evaluator.py",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/unit/test_prompt_template.py",
    "tests/unit/test_evaluation_runner.py",
    "tests/teardown/test_w3_002_evaluation_cleanliness.py",
    "tests/teardown/test_w3_003_guardrails_cleanliness.py",
)
_W3_004_EDITABLE_PATH_SET = frozenset(EXPECTED_W3_004_EDITABLE_PATHS)
EXPECTED_RAG_PRE_W7_001_IMPLEMENTATION_PATHS = (
    tuple(
        path
        for path in EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS
        if path not in _W3_004_EDITABLE_PATH_SET
    )
    + EXPECTED_W3_004_EDITABLE_PATHS
)
EXPECTED_W7_001_EDITABLE_PATHS = (
    "configs/ingestion/governed-data-foundation.yaml",
    "src/enterprise_ai_platform/ingestion/governance.py",
    "src/enterprise_ai_platform/ingestion/workflow.py",
    "tests/fakes/w7_001_data_foundation.py",
    "tests/unit/test_w7_001_data_foundation.py",
    "tests/contract/test_w7_001_data_contract.py",
    "tests/integration/test_w7_001_ingestion_composition.py",
    "tests/feature/test_w7_001_data_platform.py",
    "tests/security/test_w7_001_data_security.py",
    "tests/rollback/test_w7_001_data_rollback.py",
    "tests/teardown/test_w7_001_data_cleanliness.py",
    "src/enterprise_ai_platform/ingestion/__init__.py",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "Makefile",
    "infra/modules/storage/main.tf",
    "infra/modules/storage/variables.tf",
    "infra/modules/storage/outputs.tf",
    "infra/modules/iam/main.tf",
    "infra/modules/iam/variables.tf",
    "infra/environments/sandbox/main.tf",
    "infra/environments/sandbox/variables.tf",
    "infra/environments/sandbox/outputs.tf",
    "infra/environments/sandbox/terraform.tfvars.example",
    "policies/opa/terraform_plan.rego",
    "policies/opa/terraform_plan_test.rego",
    "tools/platformctl/policy_runner.py",
    "tests/contract/test_terraform_module_contract.py",
    "tests/security/test_terraform_security.py",
    "tests/feature/test_terraform_sandbox_plan.py",
    "tests/feature/test_policy_gate.py",
    "tests/security/test_policy_pack.py",
)
EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS = EXPECTED_RAG_PRE_W7_001_IMPLEMENTATION_PATHS + tuple(
    path
    for path in EXPECTED_W7_001_EDITABLE_PATHS
    if path not in EXPECTED_RAG_PRE_W7_001_IMPLEMENTATION_PATHS
)
EXPECTED_W7_002_EDITABLE_PATHS = (
    "configs/processing/document-quality-replay.yaml",
    "src/enterprise_ai_platform/processing/__init__.py",
    "src/enterprise_ai_platform/processing/contracts.py",
    "src/enterprise_ai_platform/processing/quality.py",
    "src/enterprise_ai_platform/processing/pipeline.py",
    "tests/fakes/w7_002_processing.py",
    "tests/unit/test_w7_002_processing.py",
    "tests/contract/test_w7_002_processing_contract.py",
    "tests/integration/test_w7_002_processing_composition.py",
    "tests/feature/test_w7_002_data_quality.py",
    "tests/security/test_w7_002_processing_security.py",
    "tests/rollback/test_w7_002_processing_rollback.py",
    "tests/teardown/test_w7_002_processing_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
)
EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS = EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS + tuple(
    path
    for path in EXPECTED_W7_002_EDITABLE_PATHS
    if path not in EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS
)
EXPECTED_W7_003_EDITABLE_PATHS = (
    "configs/ingestion/privacy-retention-lifecycle.yaml",
    "src/enterprise_ai_platform/ingestion/privacy_lifecycle.py",
    "tests/fakes/w7_003_privacy_lifecycle.py",
    "tests/unit/test_w7_003_privacy_lifecycle.py",
    "tests/contract/test_w7_003_privacy_lifecycle_contract.py",
    "tests/integration/test_w7_003_privacy_lifecycle_composition.py",
    "tests/feature/test_w7_003_privacy_lifecycle.py",
    "tests/security/test_w7_003_privacy_lifecycle_security.py",
    "tests/rollback/test_w7_003_privacy_lifecycle_rollback.py",
    "tests/teardown/test_w7_003_privacy_lifecycle_cleanliness.py",
    "src/enterprise_ai_platform/ingestion/__init__.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "tests/contract/test_vector_store.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_qdrant.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
)
EXPECTED_RAG_IMPLEMENTATION_PATHS = (
    EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS
    + tuple(
        path
        for path in EXPECTED_W7_003_EDITABLE_PATHS
        if path not in EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS
    )
    + ("tests/contract/test_w7_004_feature_management_decision.py",)
)
EXPECTED_RAG_LINKED_TRACKER_STEPS = (
    "W2-03",
    "W2-01",
    "W2-02",
    "W2-04",
    "W2-08",
    "W2-05",
    "W2-06",
    "W2-07",
    "W2-09",
    "W2-10",
    "W3-01",
    "W3-02",
    "W3-03",
    "W3-04",
    "W3-05",
    "W3-08",
    "W3-11",
    "W7-001",
    "W7-002",
    "W7-003",
    "W7-004",
)
EXPECTED_RAG_FEATURE = {
    "id": "RAG-001",
    "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
}
EXPECTED_W10_001_IMPLEMENTATION_PATHS = (
    "src/enterprise_ai_platform/retrieval/hybrid.py",
    "tests/fakes/w10_001_hybrid_retrieval.py",
    "tests/unit/test_w10_001_hybrid_retrieval.py",
    "tests/contract/test_w10_001_hybrid_retrieval_contract.py",
    "tests/integration/test_w10_001_hybrid_retrieval_composition.py",
    "tests/feature/test_w10_001_hybrid_retrieval.py",
    "tests/security/test_w10_001_hybrid_retrieval_security.py",
    "tests/rollback/test_w10_001_hybrid_retrieval_rollback.py",
    "tests/teardown/test_w10_001_hybrid_retrieval_cleanliness.py",
    ".env.example",
    "Makefile",
    "deploy/k8s/configmap.yaml",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/api/aws_composition.py",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "tests/feature/test_feature_matrix.py",
    "tests/security/test_configuration_security.py",
    "tests/unit/test_aws_composition.py",
    "tests/unit/test_config.py",
    "tests/unit/test_platformctl.py",
    "tools/platformctl/validate.py",
)
EXPECTED_RAG_002_FEATURE = {
    "id": "RAG-002",
    "implementation_paths": list(EXPECTED_W10_001_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W10-001"],
    "control_contract": {
        "capabilities": (
            "OpenSearch supports vector and hybrid retrieval; Qdrant and in-memory "
            "backends remain vector-only and never silently downgrade"
        ),
        "authorization": (
            "tenant, classification, role and group filters are identical before both "
            "channels; every returned chunk is reauthorized and failures abort the request"
        ),
        "fusion": (
            "bounded lexical and vector candidates use deterministic min-max normalization, "
            "equal weights and stable lexical-vector-chunk identity tie-breaking"
        ),
        "identity": (
            "collection, embedding, retrieval mode, standard analyzer, BM25 similarity and "
            "policy SHA-256 are bound to the OpenSearch mapping"
        ),
        "operations": (
            "two concurrent channels, two total attempts per channel, no partial results, "
            "no live index mutation and no raw vendor object escapes the adapter"
        ),
    },
}
EXPECTED_W10_002_IMPLEMENTATION_PATHS = (
    "src/enterprise_ai_platform/retrieval/reranking.py",
    "tests/fakes/w10_002_reranking.py",
    "tests/unit/test_w10_002_reranking.py",
    "tests/contract/test_w10_002_reranking_contract.py",
    "tests/integration/test_w10_002_reranking_composition.py",
    "tests/feature/test_w10_002_reranking_parity_load_cost.py",
    "tests/security/test_w10_002_reranking_security.py",
    "tests/rollback/test_w10_002_reranking_rollback.py",
    "tests/teardown/test_w10_002_reranking_cleanliness.py",
    ".env.example",
    "Makefile",
    "deploy/k8s/configmap.yaml",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/api/aws_composition.py",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/service.py",
    "tests/feature/test_feature_matrix.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_qdrant.py",
    "tests/security/test_configuration_security.py",
    "tests/unit/test_aws_composition.py",
    "tests/unit/test_config.py",
    "tests/unit/test_platformctl.py",
    "tools/platformctl/validate.py",
)
EXPECTED_RAG_003_FEATURE = {
    "id": "RAG-003",
    "implementation_paths": list(EXPECTED_W10_002_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W10-002"],
    "control_contract": {
        "identity": (
            "provider-neutral local deterministic token-overlap reranker w10-002.v1 "
            "with no network, model download or managed fallback"
        ),
        "bounds": (
            "twenty candidates and results, 256 query tokens, 384 tokens per candidate, "
            "8192 total tokens, 250 ms timeout, four concurrent calls, zero queue and zero retries"
        ),
        "authorization": (
            "every provider result and reranked output is reauthorized; any unauthorized "
            "provider candidate aborts the whole request"
        ),
        "adoption": (
            "representative owner-approved evidence must meet recall, precision, MRR, citation, "
            "authorization, latency and paid-cost gates; synthetic evidence remains indeterminate"
        ),
        "operations": (
            "default-off activation; timeout, unavailable, saturation or malformed output returns "
            "the exact authorized baseline order without another provider call"
        ),
        "backend_differences": (
            "OpenSearch supports hybrid candidates; Qdrant and in-memory remain vector-only; "
            "reranking preserves original provider-neutral chunks"
        ),
    },
}
EXPECTED_W10_003_IMPLEMENTATION_PATHS = (
    "configs/eval/rag-safety-regression-policy.yaml",
    "configs/eval/rag-safety-golden-set.jsonl",
    "src/enterprise_ai_platform/evaluation/rag_safety.py",
    "src/enterprise_ai_platform/evaluation/rag_safety_runner.py",
    "tests/fakes/w10_003_rag_evaluation.py",
    "tests/unit/test_w10_003_rag_evaluation.py",
    "tests/contract/test_w10_003_rag_evaluation_contract.py",
    "tests/integration/test_w10_003_rag_evaluation_composition.py",
    "tests/feature/test_w10_003_rag_evaluation.py",
    "tests/security/test_w10_003_rag_evaluation_security.py",
    "tests/rollback/test_w10_003_rag_evaluation_rollback.py",
    "tests/teardown/test_w10_003_rag_evaluation_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tools/evaluationctl.py",
    "tools/validate_eval_dataset.py",
    "src/enterprise_ai_platform/evaluation/__init__.py",
    "src/enterprise_ai_platform/evaluation/errors.py",
)
EXPECTED_EVAL_002_FEATURE = {
    "id": "EVAL-002",
    "implementation_paths": list(EXPECTED_W10_003_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W10-003"],
    "control_contract": {
        "dataset": (
            "protected W3 thirty-nine-case quality set plus twelve ordered synthetic INTERNAL "
            "safety cases; production data is prohibited"
        ),
        "quality": (
            "groundedness, citations, abstention and expected-error gates preserve W3 thresholds; "
            "safety failures are non-compensable"
        ),
        "identity": (
            "model, inference profile, prompt, embedding, retrieval, hybrid, reranker, index, "
            "dataset and policy identities are bound by canonical SHA-256"
        ),
        "execution": (
            "one sequential evaluation, zero evaluation retries, two attempts in each existing "
            "retry channel, at most four wire calls per logical request, thirty logical requests "
            "and a nine-hundred-second deadline"
        ),
        "release": (
            "two repeatable control runs and two repeatable candidate runs are required; "
            "any failed or indeterminate candidate identity is retained and blocked"
        ),
    },
}
EXPECTED_PRIV_003_FEATURE = {
    "id": "PRIV-003",
    "implementation_paths": list(EXPECTED_W10_003_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W10-003"],
    "control_contract": {
        "classification": "PUBLIC and INTERNAL synthetic data only; production data is prohibited",
        "separation": (
            "questions, documents and metadata remain explicitly delimited untrusted content and "
            "cannot become instructions or trusted provenance"
        ),
        "authorization": (
            "cross-tenant retrieval, unauthorized tools and approval replay fail before "
            "provider or tool execution"
        ),
        "redaction": (
            "canonical reports contain content-free counts and hashes; synthetic raw responses are "
            "restricted to the owner ACL external evidence root"
        ),
        "retention": (
            "immutable failed and passing evidence is retained for one-hundred-eighty days"
        ),
    },
}
EXPECTED_EVAL_IMPLEMENTATION_PATHS = (
    ".gitignore",
    "configs/eval/cited-rag-evaluation-policy.yaml",
    "configs/eval/golden.jsonl",
    "src/enterprise_ai_platform/evaluation/__init__.py",
    "src/enterprise_ai_platform/evaluation/errors.py",
    "src/enterprise_ai_platform/evaluation/config.py",
    "src/enterprise_ai_platform/evaluation/models.py",
    "src/enterprise_ai_platform/evaluation/dataset.py",
    "src/enterprise_ai_platform/evaluation/fixtures.py",
    "src/enterprise_ai_platform/evaluation/evaluator.py",
    "src/enterprise_ai_platform/evaluation/metrics.py",
    "src/enterprise_ai_platform/evaluation/report.py",
    "src/enterprise_ai_platform/evaluation/baseline.py",
    "src/enterprise_ai_platform/evaluation/promotion.py",
    "src/enterprise_ai_platform/evaluation/runner.py",
    "tools/validate_eval_dataset.py",
    "tests/unit/test_evaluation_dataset.py",
    "tests/unit/test_evaluation_metrics.py",
    "tests/unit/test_evaluation_runner.py",
    "tests/contract/test_evaluation_schema.py",
    "tests/contract/test_evaluation_report.py",
    "tests/feature/test_w3_002_offline_evaluation.py",
    "tests/security/test_w3_002_evaluation_security.py",
    "tests/rollback/test_w3_002_evaluation_rollback.py",
    "tests/teardown/test_w3_002_evaluation_cleanliness.py",
    "tools/evaluationctl.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
)
EXPECTED_EVAL_LINKED_TRACKER_STEPS = ("W3-06", "W3-07", "W3-10")
EXPECTED_EVAL_FEATURE = {
    "id": "EVAL-001",
    "implementation_paths": list(EXPECTED_EVAL_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_EVAL_LINKED_TRACKER_STEPS),
}
EXPECTED_API_IMPLEMENTATION_PATHS = (
    "src/enterprise_ai_platform/api/__init__.py",
    "src/enterprise_ai_platform/api/dependencies.py",
    "src/enterprise_ai_platform/api/errors.py",
    "src/enterprise_ai_platform/api/models.py",
    "src/enterprise_ai_platform/api/runtime.py",
    "src/enterprise_ai_platform/api/routes.py",
    "tests/fakes/api.py",
    "tests/unit/test_api.py",
    "tests/contract/test_api_schema.py",
    "tests/integration/test_api_dependency_composition.py",
    "tests/security/test_api_authorization.py",
    "tests/rollback/test_w4_001_api_rollback.py",
    "tests/teardown/test_w4_001_api_cleanliness.py",
    ".env.example",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/config.py",
    "tools/platformctl/validate.py",
    "tests/conftest.py",
    "tests/unit/test_config.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/security/test_configuration_security.py",
    "tests/feature/test_api_load_smoke.py",
)
EXPECTED_API_LINKED_TRACKER_STEPS = ("W4-01", "W4-02", "W4-10")
EXPECTED_API_FEATURE = {
    "id": "API-001",
    "implementation_paths": list(EXPECTED_API_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_API_LINKED_TRACKER_STEPS),
}
EXPECTED_AGENT_IMPLEMENTATION_PATHS = (
    "src/enterprise_ai_platform/agent/__init__.py",
    "src/enterprise_ai_platform/agent/authorization.py",
    "src/enterprise_ai_platform/agent/contracts.py",
    "src/enterprise_ai_platform/agent/controller.py",
    "src/enterprise_ai_platform/agent/errors.py",
    "src/enterprise_ai_platform/agent/graph.py",
    "src/enterprise_ai_platform/agent/models.py",
    "src/enterprise_ai_platform/agent/persistence.py",
    "src/enterprise_ai_platform/agent/runtime.py",
    "src/enterprise_ai_platform/agent/serialization.py",
    "src/enterprise_ai_platform/agent/tools.py",
    "tests/fakes/agent.py",
    "tests/unit/test_agent_graph.py",
    "tests/unit/test_agent_tools.py",
    "tests/unit/test_agent_budgets.py",
    "tests/unit/test_agent_persistence.py",
    "tests/contract/test_agent_schema.py",
    "tests/integration/test_agent_api_composition.py",
    "tests/security/test_agent_approval.py",
    "tests/security/test_agent_state_redaction.py",
    "tests/rollback/test_w4_002_agent_rollback.py",
    "tests/teardown/test_w4_002_agent_cleanliness.py",
    ".env.example",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/api/dependencies.py",
    "src/enterprise_ai_platform/api/errors.py",
    "src/enterprise_ai_platform/api/models.py",
    "src/enterprise_ai_platform/api/runtime.py",
    "src/enterprise_ai_platform/api/routes.py",
    "tools/platformctl/validate.py",
    "tests/conftest.py",
    "tests/unit/test_api.py",
    "tests/contract/test_api_schema.py",
    "tests/security/test_api_authorization.py",
    "tests/unit/test_config.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/security/test_configuration_security.py",
    "tests/feature/test_agent_failures.py",
)
EXPECTED_AGENT_LINKED_TRACKER_STEPS = (
    "W4-03",
    "W4-04",
    "W4-05",
    "W4-06",
    "W4-07",
    "W4-09",
)
EXPECTED_AGENT_FEATURE = {
    "id": "AGENT-001",
    "implementation_paths": list(EXPECTED_AGENT_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_AGENT_LINKED_TRACKER_STEPS),
}
EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS = (
    "configs/observability/otel-collector.local.yaml",
    "src/enterprise_ai_platform/telemetry/__init__.py",
    "src/enterprise_ai_platform/telemetry/models.py",
    "src/enterprise_ai_platform/telemetry/runtime.py",
    "tests/fakes/telemetry.py",
    "tests/unit/test_telemetry.py",
    "tests/contract/test_telemetry_schema.py",
    "tests/integration/test_telemetry_composition.py",
    "tests/feature/test_trace_correlation.py",
    "tests/security/test_telemetry_redaction.py",
    "tests/rollback/test_w4_003_telemetry_rollback.py",
    "tests/teardown/test_w4_003_telemetry_cleanliness.py",
    ".env.example",
    "feature-matrix.yaml",
    "requirements.txt",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/api/runtime.py",
    "src/enterprise_ai_platform/api/routes.py",
    "src/enterprise_ai_platform/rag/service.py",
    "src/enterprise_ai_platform/retrieval/service.py",
    "src/enterprise_ai_platform/agent/graph.py",
    "src/enterprise_ai_platform/agent/controller.py",
    "tools/platformctl/validate.py",
    "tests/conftest.py",
    "tests/unit/test_config.py",
    "tests/security/test_configuration_security.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "tests/integration/test_dependency_contract.py",
    "configs/observability/otel-collector.aws.yaml",
    "configs/observability/slo.yaml",
    "configs/chaos/fis-plan.yaml",
    "observability/alerts.yml",
    "observability/dashboards/enterprise-ai-overview.json",
    "src/enterprise_ai_platform/telemetry/export.py",
    "src/enterprise_ai_platform/telemetry/slo.py",
    "tools/w6_002_observability.py",
    "tests/fakes/observability.py",
    "tests/unit/test_w6_002_observability.py",
    "tests/contract/test_w6_002_observability_contract.py",
    "tests/integration/test_w6_002_telemetry_composition.py",
    "tests/feature/test_failure_modes.py",
    "tests/security/test_w6_002_observability_security.py",
    "tests/rollback/test_w6_002_observability_rollback.py",
    "tests/teardown/test_w6_002_observability_cleanliness.py",
    "Makefile",
)
EXPECTED_OBSERVABILITY_FEATURE = {
    "id": "OBS-001",
    "implementation_paths": list(EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W3-09", "W4-08", "W6-06", "W6-07", "W6-08", "W6-09"],
}
EXPECTED_RELEASE_IMPLEMENTATION_PATHS = (
    "configs/releases/versions/w4-known-good-v1.json",
    "configs/releases/versions/w4-synthetic-regression-v1.json",
    "src/enterprise_ai_platform/release_rollback/__init__.py",
    "src/enterprise_ai_platform/release_rollback/errors.py",
    "src/enterprise_ai_platform/release_rollback/models.py",
    "src/enterprise_ai_platform/release_rollback/identity.py",
    "src/enterprise_ai_platform/release_rollback/state.py",
    "src/enterprise_ai_platform/release_rollback/probe.py",
    "src/enterprise_ai_platform/release_rollback/service.py",
    "tools/releasectl.py",
    "tests/fakes/release_rollback.py",
    "tests/unit/test_release_rollback_identity.py",
    "tests/unit/test_release_rollback_state.py",
    "tests/contract/test_release_rollback_contract.py",
    "tests/integration/test_release_rollback_composition.py",
    "tests/feature/test_w4_011_release_rollback.py",
    "tests/smoke/test_w4_011_release_smoke.py",
    "tests/security/test_w4_011_release_rollback_security.py",
    "tests/rollback/test_w4_011_release_rollback.py",
    "tests/teardown/test_w4_011_release_rollback_cleanliness.py",
    ".gitignore",
    "Makefile",
    "feature-matrix.yaml",
    "pyproject.toml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
)
EXPECTED_RELEASE_FEATURE = {
    "id": "REL-001",
    "implementation_paths": list(EXPECTED_RELEASE_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W4-11"],
}
EXPECTED_AWS_IMPLEMENTATION_PATHS: tuple[str, ...] = (
    ".tflint.hcl",
    "infra/bootstrap/variables.tf",
    "infra/bootstrap/outputs.tf",
    "infra/environments/sandbox/variables.tf",
    "infra/environments/sandbox/outputs.tf",
    "infra/environments/sandbox/backend.hcl.example",
    "infra/modules/network/main.tf",
    "infra/modules/network/variables.tf",
    "infra/modules/network/outputs.tf",
    "infra/modules/kms/main.tf",
    "infra/modules/kms/variables.tf",
    "infra/modules/kms/outputs.tf",
    "infra/modules/storage/main.tf",
    "infra/modules/storage/variables.tf",
    "infra/modules/storage/outputs.tf",
    "infra/modules/secrets/main.tf",
    "infra/modules/secrets/variables.tf",
    "infra/modules/secrets/outputs.tf",
    "infra/modules/iam/main.tf",
    "infra/modules/iam/variables.tf",
    "infra/modules/iam/outputs.tf",
    "infra/modules/opensearch/main.tf",
    "infra/modules/opensearch/variables.tf",
    "infra/modules/opensearch/outputs.tf",
    "infra/modules/ecr/main.tf",
    "infra/modules/ecr/variables.tf",
    "infra/modules/ecr/outputs.tf",
    "policies/opa/terraform_plan.rego",
    "policies/opa/terraform_plan_test.rego",
    "tests/contract/test_terraform_module_contract.py",
    "tests/security/test_terraform_security.py",
    "tests/feature/test_terraform_sandbox_plan.py",
    "tests/teardown/test_terraform_state_boundary.py",
    ".gitignore",
    "pyproject.toml",
    "requirements-dev.txt",
    "infra/bootstrap/main.tf",
    "infra/bootstrap/versions.tf",
    "infra/environments/sandbox/main.tf",
    "infra/environments/sandbox/versions.tf",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/contracts.py",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/unit/test_platformctl_lifecycle.py",
    "tests/integration/test_dependency_contract.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "tests/teardown/test_repository_cleanliness.py",
    "tests/teardown/test_w1_002_cleanliness.py",
    "tests/teardown/test_platformctl_cleanup.py",
    ".checkov.yml",
    "policies/opa/exceptions.json",
    "tests/contract/test_policy_exception_contract.py",
    "tests/feature/test_policy_gate.py",
    "tests/rollback/test_policy_pack_rollback.py",
    "tests/security/test_policy_pack.py",
    "tests/teardown/test_policy_pack_cleanliness.py",
    "infra/environments/sandbox/terraform.tfvars.example",
)
EXPECTED_W5_004_IMPLEMENTATION_PATHS = (
    "configs/lifecycle/w5-004.json",
    "tools/platformctl/lifecycle_models.py",
    "tools/platformctl/lifecycle_io.py",
    "tools/platformctl/terraform_runner.py",
    "tools/platformctl/policy_runner.py",
    "tools/platformctl/cost.py",
    "tools/platformctl/operation_state.py",
    "tools/platformctl/plan_artifact_producer.py",
    "tools/platformctl/aws_live.py",
    "tests/fakes/platform_lifecycle.py",
    "tests/unit/test_platformctl_plan_identity.py",
    "tests/unit/test_platformctl_cost.py",
    "tests/unit/test_platformctl_operation_state.py",
    "tests/contract/test_w5_004_lifecycle_contract.py",
    "tests/integration/test_w5_004_lifecycle_composition.py",
    "tests/feature/test_w5_004_aws_lifecycle.py",
    "tests/security/test_w5_004_lifecycle_security.py",
    "tests/rollback/test_w5_004_infrastructure_rollback.py",
    "tests/teardown/test_w5_004_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "infra/bootstrap/versions.tf",
    "infra/environments/sandbox/versions.tf",
    "policies/opa/terraform_plan.rego",
    "policies/opa/terraform_plan_test.rego",
    "tools/platformctl/__init__.py",
    "tools/platformctl/cli.py",
    "tools/platformctl/contracts.py",
    "tools/platformctl/aws_inventory.py",
    "tools/platformctl/bootstrap.py",
    "tools/platformctl/plan.py",
    "tools/platformctl/deploy.py",
    "tools/platformctl/validate.py",
    "tools/platformctl/rollback.py",
    "tools/platformctl/destroy.py",
    "tools/platformctl/verify_clean.py",
    "tests/unit/test_platformctl.py",
    "tests/unit/test_platformctl_lifecycle.py",
    "tests/unit/test_platformctl_verify_clean.py",
    "tests/contract/test_platformctl_cli_contract.py",
    "tests/contract/test_terraform_module_contract.py",
    "tests/integration/test_platformctl_dry_run.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_mvp_001_platformctl.py",
    "tests/smoke/test_platformctl_help.py",
    "tests/security/test_platformctl_approval_gates.py",
    "tests/security/test_repository_security.py",
    "tests/teardown/test_platformctl_cleanup.py",
    "tests/teardown/test_terraform_state_boundary.py",
)
_W5_004_NEW_AWS_PATHS = tuple(
    path
    for path in EXPECTED_W5_004_IMPLEMENTATION_PATHS
    if path not in EXPECTED_AWS_IMPLEMENTATION_PATHS
)
EXPECTED_AWS_IMPLEMENTATION_PATHS = EXPECTED_AWS_IMPLEMENTATION_PATHS + _W5_004_NEW_AWS_PATHS
EXPECTED_AWS_FEATURE = {
    "id": "AWS-001",
    "implementation_paths": list(EXPECTED_AWS_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": [
        "W5-02",
        "W5-03",
        "W5-04",
        "W5-05",
        "W5-06",
        "W5-09",
        "W5-10",
        "W5-11",
        "W5-12",
    ],
}
EXPECTED_BEDROCK_IMPLEMENTATION_PATHS = (
    "configs/verification/bedrock-owner-test.json",
    "tools/bedrock_owner_verify.py",
    "tests/unit/test_bedrock_owner_verify.py",
    "tests/security/test_bedrock_owner_verify_security.py",
    "tests/teardown/test_bedrock_owner_verify_cleanliness.py",
)
EXPECTED_BEDROCK_FEATURE = {
    "id": "BED-001",
    "implementation_paths": list(EXPECTED_BEDROCK_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W5-02"],
}
EXPECTED_GHA_IMPLEMENTATION_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/plan-sandbox.yml",
    ".github/workflows/security-scan.yml",
    "configs/ci/w5-002.json",
    "docker/application.Dockerfile",
    "docker/application.Dockerfile.dockerignore",
    "requirements-runtime.lock",
    "requirements-ci.lock",
    "requirements-checkov.lock",
    "infra/bootstrap/.terraform.lock.hcl",
    "infra/environments/sandbox/.terraform.lock.hcl",
    "tools/w5_002_ci.py",
    "tests/unit/test_w5_002_ci.py",
    "tests/contract/test_w5_002_workflow_contract.py",
    "tests/integration/test_w5_002_ci_composition.py",
    "tests/feature/test_w5_002_supply_chain.py",
    "tests/security/test_w5_002_ci_security.py",
    "tests/rollback/test_w5_002_workflow_rollback.py",
    "tests/teardown/test_w5_002_cleanliness.py",
    ".gitignore",
    "Makefile",
    "pyproject.toml",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "tests/integration/test_dependency_contract.py",
    "tests/teardown/test_repository_cleanliness.py",
    "tests/teardown/test_terraform_state_boundary.py",
    "requirements.txt",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/release_rollback/identity.py",
    "tests/unit/test_config.py",
    "tests/unit/test_release_rollback_identity.py",
    "tests/security/test_precommit_controls.py",
    "tests/teardown/test_w4_002_agent_cleanliness.py",
    "tests/teardown/test_w4_011_release_rollback_cleanliness.py",
)
EXPECTED_GHA_FEATURE = {
    "id": "GHA-001",
    "implementation_paths": list(EXPECTED_GHA_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W5-07", "W5-08"],
}
EXPECTED_EKS_IMPLEMENTATION_PATHS: tuple[str, ...] = (
    "deploy/k8s/kustomization.yaml",
    "deploy/k8s/deployment.yaml",
    "deploy/k8s/service.yaml",
    "deploy/k8s/serviceaccount.yaml",
    "deploy/k8s/configmap.yaml",
    "deploy/k8s/networkpolicy.yaml",
    "deploy/k8s/hpa.yaml",
    "deploy/k8s/pdb.yaml",
    "tools/w6_001_k8s.py",
    "policies/opa/kubernetes.rego",
    "policies/opa/kubernetes_test.rego",
    "tests/unit/test_w6_001_k8s.py",
    "tests/contract/test_w6_001_k8s_contract.py",
    "tests/integration/test_w6_001_kubernetes_composition.py",
    "tests/feature/test_w6_001_eks.py",
    "tests/security/test_w6_001_kubernetes_security.py",
    "tests/rollback/test_w6_001_kubernetes_rollback.py",
    "tests/teardown/test_w6_001_kubernetes_cleanliness.py",
    "Makefile",
    ".github/workflows/ci.yml",
    ".checkov.yml",
    "pyproject.toml",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/integration/test_w5_002_ci_composition.py",
    "tests/security/test_policy_pack.py",
    "tests/integration/test_dependency_contract.py",
)
EXPECTED_W6_004_IMPLEMENTATION_PATHS = (
    "configs/lifecycle/w6-004.json",
    "requirements.txt",
    "requirements-runtime.lock",
    "requirements-ci.lock",
    "infra/modules/eks/main.tf",
    "infra/modules/eks/variables.tf",
    "infra/modules/eks/outputs.tf",
    "infra/modules/observability/main.tf",
    "infra/modules/observability/variables.tf",
    "infra/modules/observability/outputs.tf",
    "deploy/k8s/namespace.yaml",
    "deploy/k8s/otel-collector-configmap.yaml",
    "src/enterprise_ai_platform/api/aws_composition.py",
    "src/enterprise_ai_platform/api/sandbox_auth.py",
    "tools/platformctl/image_lifecycle.py",
    "tools/platformctl/kubernetes_lifecycle.py",
    "tools/platformctl/live_validation.py",
    "tests/fakes/w6_004_lifecycle.py",
    "tests/fixtures/w6_004/provider-computed-shapes.json",
    "tests/fixtures/w6_004/partial-apply-inventory.json",
    "tests/fixtures/w6_004/native-resource-inventory.json",
    "tests/unit/test_w6_004_lifecycle.py",
    "tests/contract/test_w6_004_lifecycle_contract.py",
    "tests/integration/test_w6_004_platform_composition.py",
    "tests/feature/test_w6_004_full_lifecycle.py",
    "tests/smoke/test_w6_004_live_smoke.py",
    "tests/security/test_w6_004_lifecycle_security.py",
    "tests/rollback/test_w6_004_full_rollback.py",
    "tests/teardown/test_w6_004_cleanliness.py",
)
EXPECTED_EKS_IMPLEMENTATION_PATHS = (
    EXPECTED_EKS_IMPLEMENTATION_PATHS + EXPECTED_W6_004_IMPLEMENTATION_PATHS
)
EXPECTED_EKS_FEATURE = {
    "id": "EKS-001",
    "implementation_paths": list(EXPECTED_EKS_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W6-02", "W6-03", "W6-04", "W6-05", "W6-004"],
    "control_contract": {
        "artifact": "two-image immutable release package; source sentinels are never deployable",
        "security": (
            "private EKS, Pod Identity, non-root containers, default-deny network "
            "and bounded egress"
        ),
        "rollback": "verified application digest and distinct saved infrastructure restore plan",
        "teardown": "owner-executed full AWS, Kubernetes, KMS-tail and cost-residue verification",
        "cost": "owner-bound lifecycle cap and per-stage stop limits required before execution",
        "owner_execution": (
            "all build, cloud, deployment, rollback and teardown commands remain owner-executed"
        ),
    },
}

EXPECTED_SERVE_IMPLEMENTATION_PATHS = (
    ".env.example",
    "Makefile",
    "deploy/k8s/configmap.yaml",
    "deploy/k8s/deployment.yaml",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/api/aws_composition.py",
    "src/enterprise_ai_platform/api/errors.py",
    "src/enterprise_ai_platform/api/models.py",
    "src/enterprise_ai_platform/api/routes.py",
    "src/enterprise_ai_platform/api/runtime.py",
    "src/enterprise_ai_platform/telemetry/__init__.py",
    "src/enterprise_ai_platform/telemetry/export.py",
    "src/enterprise_ai_platform/telemetry/models.py",
    "src/enterprise_ai_platform/telemetry/runtime.py",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tools/w6_001_k8s.py",
    "tests/unit/test_aws_composition.py",
    "tests/contract/test_api_schema.py",
    "tests/feature/test_api_load_smoke.py",
    "tests/teardown/test_w4_001_api_cleanliness.py",
    "tests/unit/test_config.py",
    "tests/security/test_configuration_security.py",
    "tests/contract/test_telemetry_schema.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/unit/test_w8_002_inference_api.py",
    "tests/contract/test_w8_002_inference_api_contract.py",
    "tests/integration/test_w8_002_inference_api_composition.py",
    "tests/feature/test_w8_002_inference_api.py",
    "tests/security/test_w8_002_inference_api_security.py",
    "tests/rollback/test_w8_002_inference_api_rollback.py",
    "tests/teardown/test_w8_002_inference_api_cleanliness.py",
)
EXPECTED_SERVE_FEATURE = {
    "id": "SERVE-002",
    "implementation_paths": list(EXPECTED_SERVE_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W8-002"],
    "control_contract": {
        "api": (
            "one existing FastAPI surface with strict non-streaming request and response contracts"
        ),
        "reliability": (
            "bounded payload, deadline, concurrency, tenant rate, circuit and drain controls"
        ),
        "security": (
            "authentication and tenant authorization precede dependency calls; "
            "telemetry is content-free"
        ),
        "operations": (
            "readiness withdrawal, bounded in-flight cancellation and dependency closure "
            "precede termination"
        ),
        "owner_execution": (
            "tests, deployment, rollback and teardown remain separately owner-controlled"
        ),
    },
}

EXPECTED_ORCH_IMPLEMENTATION_PATHS = (
    "configs/orchestration/async-workflow-policy.yaml",
    "src/enterprise_ai_platform/orchestration/__init__.py",
    "src/enterprise_ai_platform/orchestration/errors.py",
    "src/enterprise_ai_platform/orchestration/models.py",
    "src/enterprise_ai_platform/orchestration/serialization.py",
    "src/enterprise_ai_platform/orchestration/contracts.py",
    "src/enterprise_ai_platform/orchestration/policy.py",
    "src/enterprise_ai_platform/orchestration/engine.py",
    "tests/fakes/w8_003_orchestration.py",
    "tests/unit/test_w8_003_orchestration.py",
    "tests/contract/test_w8_003_orchestration_contract.py",
    "tests/integration/test_w8_003_orchestration_composition.py",
    "tests/feature/test_w8_003_async_orchestration.py",
    "tests/security/test_w8_003_orchestration_security.py",
    "tests/rollback/test_w8_003_orchestration_rollback.py",
    "tests/teardown/test_w8_003_orchestration_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
)
EXPECTED_ORCH_FEATURE = {
    "id": "ORCH-001",
    "implementation_paths": list(EXPECTED_ORCH_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W8-003"],
    "control_contract": {
        "workflows": (
            "asynchronous inference, long-running ingestion and model training share one "
            "bounded provider-neutral engine"
        ),
        "reliability": (
            "typed states, idempotency, three total attempts, exponential backoff, deadlines, "
            "compensation, resume and dead-letter routing"
        ),
        "security": (
            "tenant authorization, classification, quota, approval and artifact/provider "
            "admission precede task dispatch"
        ),
        "operations": (
            "source-only EventBridge and Step Functions-compatible contracts; no live workflow "
            "resource is created"
        ),
        "owner_execution": (
            "tests, cloud integration, deployment, rollback and teardown remain separately "
            "owner-controlled"
        ),
    },
}
EXPECTED_COST_004_IMPLEMENTATION_PATHS = (
    "configs/orchestration/async-workflow-policy.yaml",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/orchestration/models.py",
    "src/enterprise_ai_platform/orchestration/contracts.py",
    "src/enterprise_ai_platform/orchestration/policy.py",
    "src/enterprise_ai_platform/orchestration/engine.py",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/unit/test_w8_003_orchestration.py",
    "tests/contract/test_w8_003_orchestration_contract.py",
    "tests/feature/test_w8_003_async_orchestration.py",
    "tests/security/test_w8_003_orchestration_security.py",
)
EXPECTED_COST_004_FEATURE = {
    "id": "COST-004",
    "implementation_paths": list(EXPECTED_COST_004_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W8-003"],
    "control_contract": {
        "quota": (
            "four active globally, two active and eight pending per tenant, eight nonrecursive "
            "fan-out maximum"
        ),
        "approval": (
            "sensitive, high-cost and training work requires a same-tenant independent reviewer"
        ),
        "cost": "live cost ceiling remains owner-bound and live execution remains unauthorized",
        "teardown": (
            "only exact task-specific external test/cache paths may be removed after owner "
            "evidence capture"
        ),
    },
}

EXPECTED_CAP_IMPLEMENTATION_PATHS = (
    "configs/capacity/inference-capacity-cost-policy.yaml",
    "src/enterprise_ai_platform/capacity/__init__.py",
    "src/enterprise_ai_platform/capacity/errors.py",
    "src/enterprise_ai_platform/capacity/models.py",
    "src/enterprise_ai_platform/capacity/serialization.py",
    "src/enterprise_ai_platform/capacity/policy.py",
    "src/enterprise_ai_platform/capacity/evaluator.py",
    "tests/fakes/w8_004_capacity.py",
    "tests/unit/test_w8_004_capacity.py",
    "tests/contract/test_w8_004_capacity_contract.py",
    "tests/integration/test_w8_004_capacity_composition.py",
    "tests/feature/test_w8_004_capacity_cost.py",
    "tests/security/test_w8_004_capacity_security.py",
    "tests/rollback/test_w8_004_capacity_rollback.py",
    "tests/teardown/test_w8_004_capacity_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "deploy/k8s/hpa.yaml",
    "deploy/k8s/pdb.yaml",
    "tools/w6_001_k8s.py",
    "tests/unit/test_w6_001_k8s.py",
    "tests/integration/test_w6_001_kubernetes_composition.py",
)
EXPECTED_CAP_FEATURE = {
    "id": "CAP-001",
    "implementation_paths": list(EXPECTED_CAP_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W8-004"],
    "control_contract": {
        "demand": (
            "one sustained request per second, three-request spike and concurrency one, "
            "four and eight synthetic scenarios"
        ),
        "scaling": (
            "existing two-to-four replica HPA adds CPU, memory and bounded scale behavior; "
            "PDB allows at most one unavailable pod"
        ),
        "reliability": (
            "cold start, saturation, queue, timeout, dependency loss and safe termination "
            "fail closed"
        ),
        "scope": "offline aggregate evidence cannot claim production capacity",
        "owner_execution": (
            "tests, live load, cloud, deployment, rollback and teardown remain separately "
            "owner-controlled"
        ),
    },
}
EXPECTED_COST_005_IMPLEMENTATION_PATHS = (
    "configs/capacity/inference-capacity-cost-policy.yaml",
    "src/enterprise_ai_platform/capacity/__init__.py",
    "src/enterprise_ai_platform/capacity/errors.py",
    "src/enterprise_ai_platform/capacity/models.py",
    "src/enterprise_ai_platform/capacity/serialization.py",
    "src/enterprise_ai_platform/capacity/policy.py",
    "src/enterprise_ai_platform/capacity/evaluator.py",
    "tests/fakes/w8_004_capacity.py",
    "tests/unit/test_w8_004_capacity.py",
    "tests/contract/test_w8_004_capacity_contract.py",
    "tests/integration/test_w8_004_capacity_composition.py",
    "tests/feature/test_w8_004_capacity_cost.py",
    "tests/security/test_w8_004_capacity_security.py",
    "tests/rollback/test_w8_004_capacity_rollback.py",
    "tests/teardown/test_w8_004_capacity_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
)
EXPECTED_COST_005_FEATURE = {
    "id": "COST-005",
    "implementation_paths": list(EXPECTED_COST_005_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W8-004"],
    "control_contract": {
        "formula": (
            "provider token plus allocated compute plus observability and network cost divided "
            "by successful responses"
        ),
        "guardrails": (
            "sixty-dollar monthly budget, three-dollar daily alert and five-dollar maximum "
            "paid evaluation"
        ),
        "prices": "price evidence must be no more than twenty-four hours old",
        "engines": (
            "Bedrock selected; SageMaker, EKS and Karpenter conditional; Ray Serve and Triton "
            "not adopted"
        ),
        "live_cost": "cost-per-successful-request ceiling remains owner-bound",
    },
}

EXPECTED_TRAIN_IMPLEMENTATION_PATHS = (
    "configs/training/governed-sagemaker-training.yaml",
    "src/enterprise_ai_platform/training/__init__.py",
    "src/enterprise_ai_platform/training/errors.py",
    "src/enterprise_ai_platform/training/models.py",
    "src/enterprise_ai_platform/training/serialization.py",
    "src/enterprise_ai_platform/training/policy.py",
    "src/enterprise_ai_platform/training/contracts.py",
    "src/enterprise_ai_platform/training/capabilities.py",
    "src/enterprise_ai_platform/training/sagemaker.py",
    "src/enterprise_ai_platform/training/service.py",
    "tests/fakes/w9_001_training.py",
    "tests/unit/test_w9_001_training.py",
    "tests/contract/test_w9_001_training_contract.py",
    "tests/integration/test_w9_001_training_composition.py",
    "tests/feature/test_w9_001_governed_training.py",
    "tests/security/test_w9_001_training_security.py",
    "tests/rollback/test_w9_001_training_rollback.py",
    "tests/teardown/test_w9_001_training_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tools/w5_002_ci.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "src/enterprise_ai_platform/orchestration/models.py",
    "src/enterprise_ai_platform/orchestration/engine.py",
    "tests/fakes/w8_003_orchestration.py",
    "tests/integration/test_w8_003_orchestration_composition.py",
)
EXPECTED_TRAIN_FEATURE = {
    "id": "TRAIN-001",
    "implementation_paths": list(EXPECTED_TRAIN_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-001"],
    "control_contract": {
        "identities": (
            "model, data, code, container, hyperparameters, cache, policy, approval and "
            "budget are immutable and digest-bound"
        ),
        "compute": (
            "CPU or GPU capability must match before provider preparation; one active job "
            "globally and per tenant"
        ),
        "security": (
            "tenant authorization, classification, license, network isolation and secret "
            "rejection fail closed"
        ),
        "operations": (
            "offline SageMaker-compatible request rendering only; no job, model download, "
            "registry access or cloud mutation"
        ),
        "owner_execution": (
            "tests, live training, rollback and teardown remain separately owner-controlled"
        ),
    },
}
EXPECTED_COST_006_IMPLEMENTATION_PATHS = (
    "configs/training/governed-sagemaker-training.yaml",
    "src/enterprise_ai_platform/training/models.py",
    "src/enterprise_ai_platform/training/policy.py",
    "src/enterprise_ai_platform/training/sagemaker.py",
    "src/enterprise_ai_platform/training/service.py",
    "tests/contract/test_w9_001_training_contract.py",
    "tests/integration/test_w9_001_training_composition.py",
    "tests/feature/test_w9_001_governed_training.py",
    "tests/security/test_w9_001_training_security.py",
    "tests/rollback/test_w9_001_training_rollback.py",
    "tests/teardown/test_w9_001_training_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "src/enterprise_ai_platform/orchestration/models.py",
    "src/enterprise_ai_platform/orchestration/engine.py",
    "tests/integration/test_w8_003_orchestration_composition.py",
)
EXPECTED_COST_006_FEATURE = {
    "id": "COST-006",
    "implementation_paths": list(EXPECTED_COST_006_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-001"],
    "control_contract": {
        "budget": "training budget and instance price remain owner-bound",
        "limits": (
            "one instance, twenty-one-thousand-six-hundred-second runtime ceiling, "
            "one-hundred-GiB volume ceiling and zero automatic retries"
        ),
        "peft": "PEFT is disabled by default and LoRA rank cannot exceed sixty-four",
        "live_cost": "no paid training is authorized by the source contract",
    },
}

EXPECTED_MLFLOW_IMPLEMENTATION_PATHS = (
    "configs/experiments/governed-mlflow-experiment-lineage.yaml",
    "src/enterprise_ai_platform/experiment_tracking/__init__.py",
    "src/enterprise_ai_platform/experiment_tracking/errors.py",
    "src/enterprise_ai_platform/experiment_tracking/models.py",
    "src/enterprise_ai_platform/experiment_tracking/serialization.py",
    "src/enterprise_ai_platform/experiment_tracking/policy.py",
    "src/enterprise_ai_platform/experiment_tracking/contracts.py",
    "src/enterprise_ai_platform/experiment_tracking/redaction.py",
    "src/enterprise_ai_platform/experiment_tracking/mlflow.py",
    "src/enterprise_ai_platform/experiment_tracking/service.py",
    "tests/fakes/w9_002_experiment_tracking.py",
    "tests/unit/test_w9_002_experiment_tracking.py",
    "tests/contract/test_w9_002_experiment_tracking_contract.py",
    "tests/integration/test_w9_002_experiment_tracking_composition.py",
    "tests/feature/test_w9_002_experiment_lineage.py",
    "tests/security/test_w9_002_experiment_tracking_security.py",
    "tests/rollback/test_w9_002_experiment_tracking_rollback.py",
    "tests/teardown/test_w9_002_experiment_tracking_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tools/w5_002_ci.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
)
EXPECTED_MLFLOW_FEATURE = {
    "id": "MLFLOW-001",
    "implementation_paths": list(EXPECTED_MLFLOW_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-002"],
    "control_contract": {
        "identities": (
            "run, dataset, code, prompt, model, embedding, retrieval, evaluation, parameter, "
            "metric and artifact identities are canonical and digest-bound"
        ),
        "privacy": (
            "synthetic PUBLIC or INTERNAL inputs only; raw prompts, responses, questions, "
            "evidence, secrets and production data are forbidden"
        ),
        "reliability": (
            "one active run globally and per tenant, nine-hundred-second deadline, one hundred "
            "retained runs and zero automatic retries"
        ),
        "operations": (
            "process-local MLflow-compatible behavior only; no SDK, server, file store, "
            "environment binding, network or cloud mutation"
        ),
        "approval": "experiment metrics never authorize model promotion or deployment",
    },
}
EXPECTED_RET_003_IMPLEMENTATION_PATHS = (
    "configs/experiments/governed-mlflow-experiment-lineage.yaml",
    "src/enterprise_ai_platform/experiment_tracking/models.py",
    "src/enterprise_ai_platform/experiment_tracking/serialization.py",
    "src/enterprise_ai_platform/experiment_tracking/policy.py",
    "src/enterprise_ai_platform/experiment_tracking/contracts.py",
    "src/enterprise_ai_platform/experiment_tracking/mlflow.py",
    "src/enterprise_ai_platform/experiment_tracking/service.py",
    "tests/contract/test_w9_002_experiment_tracking_contract.py",
    "tests/integration/test_w9_002_experiment_tracking_composition.py",
    "tests/feature/test_w9_002_experiment_lineage.py",
    "tests/security/test_w9_002_experiment_tracking_security.py",
    "tests/rollback/test_w9_002_experiment_tracking_rollback.py",
    "tests/teardown/test_w9_002_experiment_tracking_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
)
EXPECTED_RET_003_FEATURE = {
    "id": "RET-003",
    "implementation_paths": list(EXPECTED_RET_003_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-002"],
    "control_contract": {
        "retention": "approved redacted lineage exports retain one-hundred-eighty days",
        "ordering": "disable tracking, export and verify identity before exact-run purge",
        "scope": (
            "shared resources are never deleted and managed-backend teardown remains unauthorized"
        ),
        "owner_execution": (
            "tests, export retention, purge, rollback and teardown remain separately "
            "owner-controlled"
        ),
    },
}

EXPECTED_REGISTRY_IMPLEMENTATION_PATHS = (
    "configs/model-registry/governed-sagemaker-model-promotion.yaml",
    "src/enterprise_ai_platform/model_registry/__init__.py",
    "src/enterprise_ai_platform/model_registry/errors.py",
    "src/enterprise_ai_platform/model_registry/models.py",
    "src/enterprise_ai_platform/model_registry/serialization.py",
    "src/enterprise_ai_platform/model_registry/policy.py",
    "src/enterprise_ai_platform/model_registry/contracts.py",
    "src/enterprise_ai_platform/model_registry/sagemaker.py",
    "src/enterprise_ai_platform/model_registry/registry.py",
    "src/enterprise_ai_platform/model_registry/service.py",
    "tests/fakes/w9_003_model_registry.py",
    "tests/unit/test_w9_003_model_registry.py",
    "tests/contract/test_w9_003_model_registry_contract.py",
    "tests/integration/test_w9_003_model_registry_composition.py",
    "tests/feature/test_w9_003_model_promotion.py",
    "tests/security/test_w9_003_model_registry_security.py",
    "tests/rollback/test_w9_003_model_registry_rollback.py",
    "tests/teardown/test_w9_003_model_registry_cleanliness.py",
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tools/platformctl/plan.py",
    "tools/w5_002_ci.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
)
EXPECTED_REGISTRY_FEATURE = {
    "id": "REGISTRY-001",
    "implementation_paths": list(EXPECTED_REGISTRY_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-003"],
    "control_contract": {
        "identities": (
            "package, artifact, training, experiment, approval, policy, promotion, "
            "known-good, rollback and audit identities are immutable and digest-bound"
        ),
        "approval": (
            "separate reviewer approval is required for package review, promotion and "
            "rollback; registry approval never authorizes deployment"
        ),
        "promotion": (
            "candidate-to-staging-to-production transitions are adjacent, exact-target "
            "compared, idempotent and auditable"
        ),
        "rollback": (
            "rollback restores only an exact recorded known-good identity and preserves "
            "the failed candidate"
        ),
        "operations": (
            "process-local SageMaker-compatible behavior only; no SDK, network, file store, "
            "registry mutation, model download, cloud mutation or deployment"
        ),
        "retention": (
            "disable, export and verify the audit identity before exact owner-approved "
            "deletion after one-hundred-eighty days; shared resources are never deleted"
        ),
    },
}

EXPECTED_W9_004_IMPLEMENTATION_PATHS = (
    ".github/workflows/model-supply-chain.yml",
    "configs/ci/w9-004.json",
    "policies/opa/model_supply_chain.rego",
    "policies/opa/model_supply_chain_test.rego",
    "src/enterprise_ai_platform/model_supply_chain/__init__.py",
    "src/enterprise_ai_platform/model_supply_chain/errors.py",
    "src/enterprise_ai_platform/model_supply_chain/models.py",
    "src/enterprise_ai_platform/model_supply_chain/serialization.py",
    "src/enterprise_ai_platform/model_supply_chain/policy.py",
    "src/enterprise_ai_platform/model_supply_chain/service.py",
    "tools/w9_004_supply_chain.py",
    "tests/fakes/w9_004_model_supply_chain.py",
    "tests/unit/test_w9_004_model_supply_chain.py",
    "tests/contract/test_w9_004_model_supply_chain_contract.py",
    "tests/integration/test_w9_004_model_supply_chain_composition.py",
    "tests/feature/test_w9_004_model_supply_chain.py",
    "tests/security/test_w9_004_model_supply_chain_security.py",
    "tests/rollback/test_w9_004_model_supply_chain_rollback.py",
    "tests/teardown/test_w9_004_model_supply_chain_cleanliness.py",
    ".github/workflows/ci.yml",
    ".gitignore",
    "Makefile",
    "pyproject.toml",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
    "tests/feature/test_feature_matrix.py",
    "src/enterprise_ai_platform/model_registry/models.py",
    "src/enterprise_ai_platform/model_registry/service.py",
    "src/enterprise_ai_platform/model_registry/sagemaker.py",
    "tests/fakes/w9_003_model_registry.py",
    "tests/contract/test_w9_003_model_registry_contract.py",
)
EXPECTED_SUPPLY_002_FEATURE = {
    "id": "SUPPLY-002",
    "implementation_paths": list(EXPECTED_W9_004_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-004"],
    "control_contract": {
        "identity": (
            "model, container, source, license, evaluation, training, experiment, "
            "SBOM, scan, provenance, policy and OPA decision identities are digest-bound"
        ),
        "admission": (
            "critical findings block; high findings require current candidate-specific "
            "owner treatment; disagreement and stale evidence block"
        ),
        "formats": (
            "safetensors-only weights, bounded archive inspection and executable or "
            "pickle formats denied"
        ),
        "registry": (
            "W9-003 registration and promotion require current PASS supply-chain evidence"
        ),
        "deployment": "model deployment remains NOT_AUTHORIZED",
    },
}
EXPECTED_GHA_002_FEATURE = {
    "id": "GHA-002",
    "implementation_paths": list(EXPECTED_W9_004_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W9-004"],
    "control_contract": {
        "trigger": "manual workflow_dispatch on the exact main ref and sandbox environment",
        "identity": "OIDC only, nine-hundred-second session and no static cloud credentials",
        "concurrency": "one candidate, no automatic retry and no cancel-in-progress",
        "privacy": (
            "raw hosted-runner artifacts are PUBLIC-only; INTERNAL requires a separately "
            "approved in-region runner"
        ),
        "retention": "transient workflow evidence seven days; canonical evidence 180 days",
    },
}

EXPECTED_FEATURES = (
    EXPECTED_FEATURE,
    EXPECTED_RAG_FEATURE,
    EXPECTED_EVAL_FEATURE,
    EXPECTED_API_FEATURE,
    EXPECTED_AGENT_FEATURE,
    EXPECTED_OBSERVABILITY_FEATURE,
    EXPECTED_RELEASE_FEATURE,
    EXPECTED_AWS_FEATURE,
    EXPECTED_BEDROCK_FEATURE,
    EXPECTED_GHA_FEATURE,
    EXPECTED_EKS_FEATURE,
    EXPECTED_SERVE_FEATURE,
    EXPECTED_ORCH_FEATURE,
    EXPECTED_COST_004_FEATURE,
    EXPECTED_CAP_FEATURE,
    EXPECTED_COST_005_FEATURE,
    EXPECTED_TRAIN_FEATURE,
    EXPECTED_COST_006_FEATURE,
    EXPECTED_MLFLOW_FEATURE,
    EXPECTED_RET_003_FEATURE,
    EXPECTED_REGISTRY_FEATURE,
    EXPECTED_SUPPLY_002_FEATURE,
    EXPECTED_GHA_002_FEATURE,
    EXPECTED_RAG_002_FEATURE,
    EXPECTED_RAG_003_FEATURE,
    EXPECTED_EVAL_002_FEATURE,
    EXPECTED_PRIV_003_FEATURE,
)
EXPECTED_W1_08_SECURITY_CONTROL_PATHS = (
    "tools/secret_scan.py",
    ".pre-commit-config.yaml",
    ".secrets.baseline",
    "requirements-dev.txt",
    "tests/integration/test_dependency_contract.py",
    "tests/security/test_evidence_redaction.py",
    "tests/security/test_precommit_controls.py",
    "tests/teardown/test_w1_08_cleanliness.py",
    "tools/platformctl/validate.py",
    "tests/unit/test_platformctl.py",
)

REQUIRED_DIRECTORIES = (
    "configs",
    "configs/lifecycle",
    "configs/eval",
    "configs/rag",
    "configs/rag/versions",
    "configs/observability",
    "configs/chaos",
    "configs/readiness",
    "configs/releases",
    "configs/releases/versions",
    "configs/verification",
    "configs/ci",
    "configs/processing",
    "configs/orchestration",
    "configs/capacity",
    "configs/training",
    "configs/experiments",
    "configs/model-registry",
    "data/sample",
    "data/sample/approved",
    "data/sample/restricted-fixtures",
    "docker",
    ".github",
    ".github/workflows",
    "src/enterprise_ai_platform/ingestion",
    "src/enterprise_ai_platform/evaluation",
    "src/enterprise_ai_platform/guardrails",
    "src/enterprise_ai_platform/llm",
    "src/enterprise_ai_platform/api",
    "src/enterprise_ai_platform/agent",
    "src/enterprise_ai_platform/orchestration",
    "src/enterprise_ai_platform/capacity",
    "src/enterprise_ai_platform/training",
    "src/enterprise_ai_platform/experiment_tracking",
    "src/enterprise_ai_platform/model_registry",
    "src/enterprise_ai_platform/model_supply_chain",
    "src/enterprise_ai_platform/telemetry",
    "src/enterprise_ai_platform/rag",
    "src/enterprise_ai_platform/rag_rollback",
    "src/enterprise_ai_platform/processing",
    "src/enterprise_ai_platform/release_rollback",
    "src/enterprise_ai_platform/retrieval",
    "src/enterprise_ai_platform/retrieval/adapters",
    "docs/architecture",
    "docs/adr",
    "docs/features",
    "docs/test-evidence",
    "docs/deployment-records",
    "docs/rollback-records",
    "docs/cost-estimates",
    "docs/resource-cleanliness",
    "tools/platformctl",
    "infra/bootstrap",
    "infra/modules",
    "infra/modules/network",
    "infra/modules/kms",
    "infra/modules/storage",
    "infra/modules/secrets",
    "infra/modules/iam",
    "infra/modules/opensearch",
    "infra/modules/ecr",
    "infra/environments/sandbox",
    "tests/unit",
    "tests/integration",
    "tests/contract",
    "tests/feature",
    "tests/fakes",
    "tests/smoke",
    "tests/security",
    "tests/rollback",
    "tests/teardown",
    "policies",
    "policies/opa",
    "observability",
    "observability/dashboards",
)

REQUIRED_FILES = (
    "Makefile",
    "docker-compose.yml",
    "docker/qdrant-test-runner.Dockerfile",
    "docker/qdrant-test-runner.Dockerfile.dockerignore",
    "docker/qdrant-test-runner.requirements.txt",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/authorization.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/models.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/retrieval/adapters/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "tools/__init__.py",
    "tools/platformctl/__init__.py",
    "tools/platformctl/__main__.py",
    "tools/platformctl/cli.py",
    "tools/platformctl/contracts.py",
    "tools/platformctl/aws_inventory.py",
    "tools/platformctl/bootstrap.py",
    "tools/platformctl/plan.py",
    "tools/platformctl/deploy.py",
    "tools/platformctl/validate.py",
    "tools/platformctl/rollback.py",
    "tools/platformctl/destroy.py",
    "tools/platformctl/verify_clean.py",
    "infra/bootstrap/versions.tf",
    "infra/bootstrap/main.tf",
    "infra/environments/sandbox/versions.tf",
    "infra/environments/sandbox/main.tf",
    "tests/__init__.py",
    "tests/unit/__init__.py",
    "tests/unit/test_platformctl.py",
    "tests/unit/test_platformctl_lifecycle.py",
    "tests/unit/test_platformctl_verify_clean.py",
    "tests/unit/test_models.py",
    "tests/integration/__init__.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_repository_layout.py",
    "tests/integration/test_platformctl_dry_run.py",
    "tests/integration/test_qdrant.py",
    "tests/contract/test_platformctl_cli_contract.py",
    "tests/contract/test_vector_store.py",
    "tests/feature/__init__.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_mvp_001_platformctl.py",
    "tests/feature/test_w2_001_retrieval_contract.py",
    "tests/fakes/aws_inventory.py",
    "tests/smoke/__init__.py",
    "tests/smoke/test_platformctl_help.py",
    "tests/security/__init__.py",
    "tests/security/test_platformctl_approval_gates.py",
    "tests/security/test_tenant_isolation.py",
    *EXPECTED_RAG_IMPLEMENTATION_PATHS,
    *EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    *EXPECTED_API_IMPLEMENTATION_PATHS,
    *EXPECTED_AGENT_IMPLEMENTATION_PATHS,
    *EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS,
    *EXPECTED_RELEASE_IMPLEMENTATION_PATHS,
    *EXPECTED_AWS_IMPLEMENTATION_PATHS,
    *EXPECTED_BEDROCK_IMPLEMENTATION_PATHS,
    *EXPECTED_GHA_IMPLEMENTATION_PATHS,
    *EXPECTED_W1_08_SECURITY_CONTROL_PATHS,
    *EXPECTED_W6_003_IMPLEMENTATION_PATHS,
    *EXPECTED_W6_004_IMPLEMENTATION_PATHS,
    *EXPECTED_ORCH_IMPLEMENTATION_PATHS,
    *EXPECTED_CAP_IMPLEMENTATION_PATHS,
    *EXPECTED_TRAIN_IMPLEMENTATION_PATHS,
    *EXPECTED_MLFLOW_IMPLEMENTATION_PATHS,
    *EXPECTED_REGISTRY_IMPLEMENTATION_PATHS,
    *EXPECTED_W9_004_IMPLEMENTATION_PATHS,
    *EXPECTED_W10_001_IMPLEMENTATION_PATHS,
    *EXPECTED_W10_002_IMPLEMENTATION_PATHS,
    *EXPECTED_W10_003_IMPLEMENTATION_PATHS,
    "tests/teardown/__init__.py",
    "tests/teardown/test_platformctl_cleanup.py",
    "tests/teardown/test_w2_001_qdrant_lifecycle.py",
    *EXPECTED_EKS_IMPLEMENTATION_PATHS[:18],
)


class MatrixValidationError(ValueError):
    """Raised when feature-matrix.yaml violates the approved contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixValidationError("feature matrix must not contain duplicate keys")
        result[key] = value
    return result


def validate_feature_matrix(data: object) -> list[str]:
    """Return all deviations from the owner-approved feature matrix contract."""
    if not isinstance(data, dict):
        return ["feature matrix must contain a top-level object"]

    errors: list[str] = []
    expected_top_level = {
        "schema_version",
        "project",
        "permitted_statuses",
        "features",
    }
    actual_top_level = set(data)
    if actual_top_level != expected_top_level:
        errors.append("top-level keys must be exactly: " + ", ".join(sorted(expected_top_level)))

    if data.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA_VERSION!r}")

    if data.get("project") != EXPECTED_PROJECT:
        errors.append("project metadata does not match the owner-approved values")

    statuses = data.get("permitted_statuses")
    if statuses != list(PERMITTED_STATUSES):
        errors.append("permitted_statuses do not match the exact approved labels")

    features = data.get("features")
    if not isinstance(features, list):
        errors.append("features must be a list")
    elif features != list(EXPECTED_FEATURES):
        errors.append(
            "features must exactly match the owner-approved ordered feature set: "
            "MVP-001, RAG-001, EVAL-001, API-001, AGENT-001, OBS-001, "
            "REL-001, AWS-001, BED-001, GHA-001, EKS-001, SERVE-002, ORCH-001, "
            "COST-004, CAP-001, COST-005"
            ", TRAIN-001, COST-006, MLFLOW-001, RET-003, REGISTRY-001, "
            "SUPPLY-002, GHA-002, RAG-002, RAG-003, EVAL-002, PRIV-003"
        )

    return errors


def load_feature_matrix(path: Path) -> dict[str, object]:
    """Load JSON-compatible YAML and enforce the approved contract."""
    try:
        raw_data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MatrixValidationError(f"cannot read {path}: {exc}") from exc

    try:
        data = cast(
            object,
            json.loads(raw_data, object_pairs_hook=_reject_duplicate_keys),
        )
    except json.JSONDecodeError as exc:
        raise MatrixValidationError(
            f"feature matrix must be valid JSON-compatible YAML: {exc}"
        ) from exc

    errors = validate_feature_matrix(data)
    if errors:
        raise MatrixValidationError("; ".join(errors))
    if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
        raise MatrixValidationError("feature matrix keys must be strings")
    return cast(dict[str, object], data)


def validate_control_matrix(rows: tuple[ControlMatrixRow, ...]) -> tuple[ControlMatrixRow, ...]:
    """Require every mandatory control to have conclusive, identity-bound evidence."""
    from .contracts import validate_sha256
    from .lifecycle_models import ControlResult

    if not rows or len({row.control_id for row in rows}) != len(rows):
        raise ContractError("CONTROL_MATRIX_IDENTITY_INVALID")
    known = {row.control_id for row in rows}
    for row in rows:
        if not row.executor or not row.expected_result:
            raise ContractError("CONTROL_MATRIX_FIELDS_REQUIRED")
        if any(
            dependency not in known or dependency == row.control_id
            for dependency in row.dependency_ids
        ):
            raise ContractError("CONTROL_MATRIX_DEPENDENCY_INVALID")
        if row.mandatory and row.result in {
            ControlResult.NO_DATA,
            ControlResult.NOT_RUN,
            ControlResult.INDETERMINATE,
        }:
            raise ContractError("MANDATORY_CONTROL_NOT_CONCLUSIVE")
        if row.result in {ControlResult.PASS, ControlResult.FAIL} and row.evidence is None:
            raise ContractError("CONCLUSIVE_CONTROL_REQUIRES_EVIDENCE")
        if row.evidence is not None:
            validate_sha256(row.evidence.sha256)
    dependencies = {row.control_id: row.dependency_ids for row in rows}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(control_id: str) -> None:
        if control_id in visiting:
            raise ContractError("CONTROL_MATRIX_DEPENDENCY_CYCLE")
        if control_id in visited:
            return
        visiting.add(control_id)
        for dependency in dependencies[control_id]:
            visit(dependency)
        visiting.remove(control_id)
        visited.add(control_id)

    for control_id in dependencies:
        visit(control_id)
    return rows


def validate_production_readiness_reference(value: ProductionReadinessReference) -> None:
    """A reviewer name alone never establishes production readiness."""
    from .contracts import parse_utc_timestamp, validate_sha256
    from .lifecycle_models import W7_001_SCHEMA_VERSION

    if value.schema_version != W7_001_SCHEMA_VERSION or value.reviewer != "Gyan Prakash Rai":
        raise ContractError("PRODUCTION_READINESS_REFERENCE_INVALID")
    validate_sha256(value.review_sha256)
    if (value.decision is None) != (value.decided_at is None):
        raise ContractError("PRODUCTION_READINESS_DECISION_INCOMPLETE")
    if value.decision is not None:
        if value.decision not in {"APPROVED", "REJECTED"}:
            raise ContractError("PRODUCTION_READINESS_DECISION_INVALID")
        parse_utc_timestamp(value.decided_at or "", "production readiness decided_at")


def repository_root() -> Path:
    """Return the repository root without consulting external state."""
    return Path(__file__).resolve().parents[2]


def validate_repository(root: Path | None = None) -> list[str]:
    """Read repository state and return code-stage validation errors."""
    target = (root or repository_root()).resolve()
    errors: list[str] = []

    for relative_path in REQUIRED_DIRECTORIES:
        if not (target / relative_path).is_dir():
            errors.append(f"missing required directory: {relative_path}")

    for relative_path in REQUIRED_FILES:
        if not (target / relative_path).is_file():
            errors.append(f"missing required file: {relative_path}")

    lifecycle_config = target / "configs/lifecycle/w5-004.json"
    if lifecycle_config.is_file():
        try:
            lifecycle_values = load_lifecycle_config(lifecycle_config)
            if lifecycle_values["schema_version"] != OPERATIONAL_SCHEMA_VERSION:
                errors.append("operational lifecycle configuration must use v2")
        except ContractError as exc:
            errors.append(f"invalid W5-004 lifecycle configuration: {exc}")

    w6_004_config = target / "configs/lifecycle/w6-004.json"
    if w6_004_config.is_file():
        try:
            validate_source_contract(w6_004_config)
        except W6004Error as exc:
            errors.append(f"invalid W6-004 lifecycle source contract: {exc}")

    for relative_path in (
        "policies/opa/terraform.rego",
        "policies/opa/terraform_test.rego",
    ):
        if (target / relative_path).exists():
            errors.append(f"forbidden duplicate policy path: {relative_path}")

    for relative_directory in ("policies/checkov", "checks"):
        policy_directory = target / relative_directory
        if policy_directory.is_dir() and any(policy_directory.rglob("*.py")):
            errors.append(f"unexpected custom Checkov policy path beneath: {relative_directory}")

    opa_policy = target / "policies/opa/terraform_plan.rego"
    if opa_policy.is_file():
        policy_lines = opa_policy.read_text(encoding="utf-8").splitlines()
        first_policy_line = next((line for line in policy_lines if line.strip()), "")
        if first_policy_line != "package enterprise_ai.terraform.plan":
            errors.append("OPA policy package must equal enterprise_ai.terraform.plan")

    exception_registry = target / "policies/opa/exceptions.json"
    if exception_registry.is_file():
        try:
            exception_data = json.loads(exception_registry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid W5 policy exception registry: {exc}")
        else:
            if (
                not isinstance(exception_data, dict)
                or exception_data.get("schema_version") != "w5-003.policy-exceptions.v1"
            ):
                errors.append(
                    "policy exception schema_version must equal w5-003.policy-exceptions.v1"
                )

    matrix_path = target / "feature-matrix.yaml"
    if matrix_path.is_file():
        try:
            load_feature_matrix(matrix_path)
        except MatrixValidationError as exc:
            errors.append(str(exc))

    return errors
