"""Read-only validation of the approved repository contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from .contracts import ContractError
from .lifecycle_io import load_lifecycle_config
from .lifecycle_models import OPERATIONAL_SCHEMA_VERSION

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
EXPECTED_FEATURE = {
    "id": "MVP-001",
    "status": "Not Started",
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
    "configs/rag/versions/w3-002-v1.json",
    "configs/rag/versions/w3-004-synthetic-regression-v1.json",
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
EXPECTED_RAG_IMPLEMENTATION_PATHS = (
    tuple(
        path
        for path in EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS
        if path not in _W3_004_EDITABLE_PATH_SET
    )
    + EXPECTED_W3_004_EDITABLE_PATHS
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
)
EXPECTED_RAG_FEATURE = {
    "id": "RAG-001",
    "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
}
EXPECTED_EVAL_IMPLEMENTATION_PATHS = (
    ".gitignore",
    "configs/eval/w3-002.yaml",
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
)
EXPECTED_OBSERVABILITY_FEATURE = {
    "id": "OBS-001",
    "implementation_paths": list(EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W3-09", "W4-08"],
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
    "configs/releases",
    "configs/releases/versions",
    "configs/verification",
    "configs/ci",
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
    "src/enterprise_ai_platform/telemetry",
    "src/enterprise_ai_platform/rag",
    "src/enterprise_ai_platform/rag_rollback",
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
    "tests/teardown/__init__.py",
    "tests/teardown/test_platformctl_cleanup.py",
    "tests/teardown/test_w2_001_qdrant_lifecycle.py",
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
            "REL-001, AWS-001, BED-001, GHA-001"
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
