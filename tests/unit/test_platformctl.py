"""Unit tests for the read-only platformctl contract."""

from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from tools.platformctl import __version__

# EKS-001 repository-path validation is exercised by tests/unit/test_w6_001_k8s.py.
from tools.platformctl.cli import (
    EXPECTED_FEATURE,
    EXPECTED_FEATURES,
    EXPECTED_PROJECT,
    EXPECTED_SCHEMA_VERSION,
    PERMITTED_STATUSES,
    REQUIRED_DIRECTORIES,
    REQUIRED_FILES,
    build_parser,
    validate_feature_matrix,
    validate_repository,
)
from tools.platformctl.validate import (
    EXPECTED_AGENT_IMPLEMENTATION_PATHS,
    EXPECTED_AGENT_LINKED_TRACKER_STEPS,
    EXPECTED_API_IMPLEMENTATION_PATHS,
    EXPECTED_API_LINKED_TRACKER_STEPS,
    EXPECTED_AWS_IMPLEMENTATION_PATHS,
    EXPECTED_BEDROCK_IMPLEMENTATION_PATHS,
    EXPECTED_CAP_IMPLEMENTATION_PATHS,
    EXPECTED_COST_004_IMPLEMENTATION_PATHS,
    EXPECTED_COST_005_IMPLEMENTATION_PATHS,
    EXPECTED_COST_006_IMPLEMENTATION_PATHS,
    EXPECTED_DR_001_FEATURE,
    EXPECTED_EVAL_002_FEATURE,
    EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    EXPECTED_EVAL_LINKED_TRACKER_STEPS,
    EXPECTED_FIS_002_FEATURE,
    EXPECTED_GHA_IMPLEMENTATION_PATHS,
    EXPECTED_INC_001_FEATURE,
    EXPECTED_MLFLOW_IMPLEMENTATION_PATHS,
    EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS,
    EXPECTED_ORCH_IMPLEMENTATION_PATHS,
    EXPECTED_PRIV_003_FEATURE,
    EXPECTED_RAG_002_FEATURE,
    EXPECTED_RAG_003_FEATURE,
    EXPECTED_RAG_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_LINKED_TRACKER_STEPS,
    EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W7_001_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS,
    EXPECTED_REGISTRY_IMPLEMENTATION_PATHS,
    EXPECTED_RELEASE_IMPLEMENTATION_PATHS,
    EXPECTED_RES_002_FEATURE,
    EXPECTED_RET_003_IMPLEMENTATION_PATHS,
    EXPECTED_RPO_001_FEATURE,
    EXPECTED_RUNNER_001_FEATURE,
    EXPECTED_SERVE_IMPLEMENTATION_PATHS,
    EXPECTED_TRAIN_IMPLEMENTATION_PATHS,
    EXPECTED_W1_08_SECURITY_CONTROL_PATHS,
    EXPECTED_W3_003_EDITABLE_PATHS,
    EXPECTED_W3_004_EDITABLE_PATHS,
    EXPECTED_W5_004_IMPLEMENTATION_PATHS,
    EXPECTED_W6_003_IMPLEMENTATION_PATHS,
    EXPECTED_W7_001_EDITABLE_PATHS,
    EXPECTED_W7_002_EDITABLE_PATHS,
    EXPECTED_W7_003_EDITABLE_PATHS,
    EXPECTED_W9_004_IMPLEMENTATION_PATHS,
    EXPECTED_W10_001_IMPLEMENTATION_PATHS,
    EXPECTED_W10_002_IMPLEMENTATION_PATHS,
    EXPECTED_W10_003_IMPLEMENTATION_PATHS,
    EXPECTED_W11_002_IMPLEMENTATION_PATHS,
    EXPECTED_W11_003_IMPLEMENTATION_PATHS,
    EXPECTED_W11_004_IMPLEMENTATION_PATHS,
)


def approved_matrix() -> dict[str, object]:
    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "project": dict(EXPECTED_PROJECT),
        "permitted_statuses": list(PERMITTED_STATUSES),
        "features": [deepcopy(feature) for feature in EXPECTED_FEATURES],
    }


class PlatformCtlUnitTests(unittest.TestCase):
    def test_version_is_an_explicit_pre_release_version(self) -> None:
        self.assertEqual("0.2.0", __version__)

    def test_parser_exposes_w1_004_lifecycle_subcommands(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["validate"])
        self.assertEqual("validate", arguments.command)
        help_text = parser.format_help()
        for command in (
            "validate",
            "bootstrap-plan",
            "bootstrap-apply",
            "platform-plan",
            "policy-review",
            "cost-review",
            "platform-apply",
            "aws-verify",
            "infrastructure-rollback",
            "destroy-plan",
            "purge-sandbox",
            "platform-destroy",
            "bootstrap-destroy",
            "verify-clean",
        ):
            self.assertIn(command, help_text)
        self.assertNotIn("--execute", help_text)

    def test_approved_matrix_has_no_errors(self) -> None:
        self.assertIs(EXPECTED_FEATURE, EXPECTED_FEATURES[0])
        self.assertEqual(
            [
                "MVP-001",
                "RAG-001",
                "EVAL-001",
                "API-001",
                "AGENT-001",
                "OBS-001",
                "REL-001",
                "AWS-001",
                "BED-001",
                "GHA-001",
                "EKS-001",
                "SERVE-002",
                "ORCH-001",
                "COST-004",
                "CAP-001",
                "COST-005",
                "TRAIN-001",
                "COST-006",
                "MLFLOW-001",
                "RET-003",
                "REGISTRY-001",
                "SUPPLY-002",
                "GHA-002",
                "RAG-002",
                "RAG-003",
                "EVAL-002",
                "PRIV-003",
                "FIS-002",
                "RES-002",
                "DR-001",
                "RPO-001",
                "INC-001",
                "RUNNER-001",
            ],
            [feature["id"] for feature in EXPECTED_FEATURES],
        )
        self.assertEqual([], validate_feature_matrix(approved_matrix()))

    def test_w8_002_inference_hardening_manifest_is_exact(self) -> None:
        self.assertEqual(35, len(EXPECTED_SERVE_IMPLEMENTATION_PATHS))
        self.assertEqual(35, len(set(EXPECTED_SERVE_IMPLEMENTATION_PATHS)))
        self.assertEqual("SERVE-002", EXPECTED_FEATURES[11]["id"])
        self.assertEqual(["W8-002"], EXPECTED_FEATURES[11]["linked_tracker_steps"])

    def test_w8_003_orchestration_and_cost_manifests_are_exact(self) -> None:
        self.assertEqual(24, len(EXPECTED_ORCH_IMPLEMENTATION_PATHS))
        self.assertEqual(24, len(set(EXPECTED_ORCH_IMPLEMENTATION_PATHS)))
        self.assertEqual(14, len(EXPECTED_COST_004_IMPLEMENTATION_PATHS))
        self.assertEqual(14, len(set(EXPECTED_COST_004_IMPLEMENTATION_PATHS)))
        self.assertEqual("ORCH-001", EXPECTED_FEATURES[12]["id"])
        self.assertEqual("COST-004", EXPECTED_FEATURES[13]["id"])
        self.assertEqual(["W8-003"], EXPECTED_FEATURES[12]["linked_tracker_steps"])
        self.assertEqual(["W8-003"], EXPECTED_FEATURES[13]["linked_tracker_steps"])

    def test_w8_004_capacity_and_cost_manifests_are_exact(self) -> None:
        self.assertEqual(25, len(EXPECTED_CAP_IMPLEMENTATION_PATHS))
        self.assertEqual(25, len(set(EXPECTED_CAP_IMPLEMENTATION_PATHS)))
        self.assertEqual(20, len(EXPECTED_COST_005_IMPLEMENTATION_PATHS))
        self.assertEqual(20, len(set(EXPECTED_COST_005_IMPLEMENTATION_PATHS)))
        self.assertEqual("CAP-001", EXPECTED_FEATURES[14]["id"])
        self.assertEqual("COST-005", EXPECTED_FEATURES[15]["id"])
        self.assertEqual(["W8-004"], EXPECTED_FEATURES[14]["linked_tracker_steps"])
        self.assertEqual(["W8-004"], EXPECTED_FEATURES[15]["linked_tracker_steps"])
        self.assertIn("configs/capacity", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/capacity", REQUIRED_DIRECTORIES)
        for path in EXPECTED_CAP_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w9_001_training_and_cost_manifests_are_exact(self) -> None:
        self.assertEqual(31, len(EXPECTED_TRAIN_IMPLEMENTATION_PATHS))
        self.assertEqual(31, len(set(EXPECTED_TRAIN_IMPLEMENTATION_PATHS)))
        self.assertEqual(20, len(EXPECTED_COST_006_IMPLEMENTATION_PATHS))
        self.assertEqual(20, len(set(EXPECTED_COST_006_IMPLEMENTATION_PATHS)))
        self.assertEqual("TRAIN-001", EXPECTED_FEATURES[16]["id"])
        self.assertEqual("COST-006", EXPECTED_FEATURES[17]["id"])
        self.assertEqual(["W9-001"], EXPECTED_FEATURES[16]["linked_tracker_steps"])
        self.assertEqual(["W9-001"], EXPECTED_FEATURES[17]["linked_tracker_steps"])
        self.assertIn("configs/training", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/training", REQUIRED_DIRECTORIES)
        for path in EXPECTED_TRAIN_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w9_002_lineage_and_retention_manifests_are_exact(self) -> None:
        self.assertEqual(27, len(EXPECTED_MLFLOW_IMPLEMENTATION_PATHS))
        self.assertEqual(27, len(set(EXPECTED_MLFLOW_IMPLEMENTATION_PATHS)))
        self.assertEqual(19, len(EXPECTED_RET_003_IMPLEMENTATION_PATHS))
        self.assertEqual(19, len(set(EXPECTED_RET_003_IMPLEMENTATION_PATHS)))
        self.assertEqual("MLFLOW-001", EXPECTED_FEATURES[18]["id"])
        self.assertEqual("RET-003", EXPECTED_FEATURES[19]["id"])
        self.assertEqual(["W9-002"], EXPECTED_FEATURES[18]["linked_tracker_steps"])
        self.assertEqual(["W9-002"], EXPECTED_FEATURES[19]["linked_tracker_steps"])
        self.assertIn("configs/experiments", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/experiment_tracking", REQUIRED_DIRECTORIES)
        for path in EXPECTED_MLFLOW_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w9_003_model_registry_manifest_is_exact(self) -> None:
        self.assertEqual(27, len(EXPECTED_REGISTRY_IMPLEMENTATION_PATHS))
        self.assertEqual(27, len(set(EXPECTED_REGISTRY_IMPLEMENTATION_PATHS)))
        self.assertEqual("REGISTRY-001", EXPECTED_FEATURES[20]["id"])
        self.assertEqual(["W9-003"], EXPECTED_FEATURES[20]["linked_tracker_steps"])
        self.assertIn("configs/model-registry", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/model_registry", REQUIRED_DIRECTORIES)
        for path in EXPECTED_REGISTRY_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w9_004_model_supply_chain_manifest_is_exact(self) -> None:
        self.assertEqual(32, len(EXPECTED_W9_004_IMPLEMENTATION_PATHS))
        self.assertEqual(32, len(set(EXPECTED_W9_004_IMPLEMENTATION_PATHS)))
        self.assertEqual("SUPPLY-002", EXPECTED_FEATURES[21]["id"])
        self.assertEqual("GHA-002", EXPECTED_FEATURES[22]["id"])
        self.assertEqual(["W9-004"], EXPECTED_FEATURES[21]["linked_tracker_steps"])
        self.assertEqual(["W9-004"], EXPECTED_FEATURES[22]["linked_tracker_steps"])
        self.assertIn("src/enterprise_ai_platform/model_supply_chain", REQUIRED_DIRECTORIES)
        for path in EXPECTED_W9_004_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w10_001_hybrid_retrieval_manifest_is_exact(self) -> None:
        self.assertEqual(23, len(EXPECTED_W10_001_IMPLEMENTATION_PATHS))
        self.assertEqual(23, len(set(EXPECTED_W10_001_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_RAG_002_FEATURE, EXPECTED_FEATURES[23])
        self.assertEqual(["W10-001"], EXPECTED_FEATURES[23]["linked_tracker_steps"])
        for path in EXPECTED_W10_001_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w10_002_reranking_manifest_is_exact(self) -> None:
        self.assertEqual(29, len(EXPECTED_W10_002_IMPLEMENTATION_PATHS))
        self.assertEqual(29, len(set(EXPECTED_W10_002_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_RAG_003_FEATURE, EXPECTED_FEATURES[24])
        self.assertEqual(["W10-002"], EXPECTED_FEATURES[24]["linked_tracker_steps"])
        for path in EXPECTED_W10_002_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w10_003_evaluation_and_privacy_manifest_is_exact(self) -> None:
        self.assertEqual(21, len(EXPECTED_W10_003_IMPLEMENTATION_PATHS))
        self.assertEqual(21, len(set(EXPECTED_W10_003_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_EVAL_002_FEATURE, EXPECTED_FEATURES[25])
        self.assertEqual(EXPECTED_PRIV_003_FEATURE, EXPECTED_FEATURES[26])
        self.assertEqual(["W10-003"], EXPECTED_FEATURES[25]["linked_tracker_steps"])
        self.assertEqual(["W10-003"], EXPECTED_FEATURES[26]["linked_tracker_steps"])
        for path in EXPECTED_W10_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w11_002_chaos_and_resilience_manifests_are_exact_and_blocked(self) -> None:
        self.assertEqual(19, len(EXPECTED_W11_002_IMPLEMENTATION_PATHS))
        self.assertEqual(19, len(set(EXPECTED_W11_002_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_FIS_002_FEATURE, EXPECTED_FEATURES[27])
        self.assertEqual(EXPECTED_RES_002_FEATURE, EXPECTED_FEATURES[28])
        for feature in EXPECTED_FEATURES[27:29]:
            self.assertEqual("Blocked", feature["status"])
            self.assertEqual(["W11-002"], feature["linked_tracker_steps"])
        for path in EXPECTED_W11_002_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w11_003_disaster_recovery_manifests_are_exact_and_blocked(self) -> None:
        self.assertEqual(19, len(EXPECTED_W11_003_IMPLEMENTATION_PATHS))
        self.assertEqual(19, len(set(EXPECTED_W11_003_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_DR_001_FEATURE, EXPECTED_FEATURES[29])
        self.assertEqual(EXPECTED_RPO_001_FEATURE, EXPECTED_FEATURES[30])
        for feature in EXPECTED_FEATURES[29:31]:
            self.assertEqual("Blocked", feature["status"])
            self.assertEqual(["W11-003"], feature["linked_tracker_steps"])
        self.assertIn("configs/recovery", REQUIRED_DIRECTORIES)
        for path in EXPECTED_W11_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w11_004_incident_and_runner_manifests_are_exact_and_blocked(self) -> None:
        self.assertEqual(25, len(EXPECTED_W11_004_IMPLEMENTATION_PATHS))
        self.assertEqual(25, len(set(EXPECTED_W11_004_IMPLEMENTATION_PATHS)))
        self.assertEqual(EXPECTED_INC_001_FEATURE, EXPECTED_FEATURES[31])
        self.assertEqual(EXPECTED_RUNNER_001_FEATURE, EXPECTED_FEATURES[32])
        for feature in EXPECTED_FEATURES[31:33]:
            self.assertEqual("Blocked", feature["status"])
            self.assertEqual(["W11-004"], feature["linked_tracker_steps"])
        for directory in ("configs/incidents", "tools/powershell", "tests/pester"):
            self.assertIn(directory, REQUIRED_DIRECTORIES)
        for path in EXPECTED_W11_004_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w6_003_readiness_extends_mvp_without_claiming_completion(self) -> None:
        self.assertEqual(20, len(EXPECTED_W6_003_IMPLEMENTATION_PATHS))
        self.assertEqual(20, len(set(EXPECTED_W6_003_IMPLEMENTATION_PATHS)))
        self.assertEqual("In Progress", EXPECTED_FEATURES[0]["status"])
        self.assertEqual(
            list(EXPECTED_W6_003_IMPLEMENTATION_PATHS),
            EXPECTED_FEATURES[0]["implementation_paths"],
        )
        for path in EXPECTED_W6_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_unapproved_status_is_rejected(self) -> None:
        matrix = approved_matrix()
        matrix["features"][0]["status"] = "Complete"  # type: ignore[index]
        errors = validate_feature_matrix(matrix)
        self.assertTrue(any("MVP-001" in error for error in errors))

    def test_additional_feature_is_rejected(self) -> None:
        matrix = approved_matrix()
        matrix["features"].append(  # type: ignore[union-attr]
            {
                "id": "W1-03",
                "status": "Not Started",
                "linked_tracker_steps": [],
            }
        )
        errors = validate_feature_matrix(matrix)
        self.assertTrue(any("owner-approved ordered feature set" in error for error in errors))

    def test_missing_duplicate_or_reordered_feature_is_rejected(self) -> None:
        features = approved_matrix()["features"]
        variants = (
            features[:1],  # type: ignore[index]
            list(reversed(features)),  # type: ignore[arg-type]
            [features[0], features[0]],  # type: ignore[index]
        )
        for variant in variants:
            with self.subTest(variant=variant):
                matrix = approved_matrix()
                matrix["features"] = variant
                self.assertTrue(validate_feature_matrix(matrix))

    def test_w2_required_paths_extend_the_repository_contract(self) -> None:
        self.assertIn("docker", REQUIRED_DIRECTORIES)
        self.assertIn(
            "src/enterprise_ai_platform/retrieval/adapters",
            REQUIRED_DIRECTORIES,
        )
        for required_file in (
            "docker-compose.yml",
            "docker/qdrant-test-runner.Dockerfile",
            "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
            "tests/integration/test_qdrant.py",
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
            "configs/pii-policy.yaml",
            "configs/eval/w2-starter.jsonl",
            "data/sample/corpus-manifest.json",
            "src/enterprise_ai_platform/ingestion/pipeline.py",
            "tests/unit/test_chunking.py",
            "tests/unit/test_ingestion.py",
            "tests/security/test_pii.py",
            "tests/rollback/test_w2_003_ingestion_rollback.py",
            "tests/teardown/test_w2_003_ingestion_cleanliness.py",
            "docker-compose.w2-004.yml",
            "docker/local-retrieval-runner.Dockerfile",
            "docker/local-retrieval-runner.Dockerfile.dockerignore",
            "docker/local-retrieval-runner.requirements.txt",
            "src/enterprise_ai_platform/retrieval/service.py",
            "tools/verify_w2_004_local.py",
            "tests/unit/test_retrieval_service.py",
            "tests/unit/test_verify_w2_004_local.py",
            "tests/contract/test_retrieval_service.py",
            "tests/feature/test_local_retrieval.py",
            "tests/security/test_w2_004_retrieval_security.py",
            "tests/rollback/test_w2_004_local_rollback.py",
            "tests/teardown/test_w2_004_retrieval_cleanliness.py",
        ):
            self.assertIn(required_file, REQUIRED_FILES)

    def test_missing_repository_reports_errors_without_creating_paths(self) -> None:
        missing_root = Path("definitely-not-an-enterprise-ai-platform-root")
        errors = validate_repository(missing_root)
        self.assertTrue(errors)
        self.assertFalse(missing_root.exists())

    def test_w3_cited_rag_contract_is_exactly_appended(self) -> None:
        expected_w3_paths = (
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

        self.assertTrue(set(expected_w3_paths).issubset(EXPECTED_RAG_IMPLEMENTATION_PATHS))
        for path in expected_w3_paths:
            self.assertEqual(1, EXPECTED_RAG_IMPLEMENTATION_PATHS.count(path))
        self.assertEqual(
            ("W3-01", "W3-02", "W3-03", "W3-04"),
            EXPECTED_RAG_LINKED_TRACKER_STEPS[
                EXPECTED_RAG_LINKED_TRACKER_STEPS.index(
                    "W3-01"
                ) : EXPECTED_RAG_LINKED_TRACKER_STEPS.index("W3-05")
            ],
        )
        self.assertIn("src/enterprise_ai_platform/llm", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/rag", REQUIRED_DIRECTORIES)

    def test_w3_003_guardrail_contract_is_exactly_appended(self) -> None:
        self.assertEqual(20, len(EXPECTED_W3_003_EDITABLE_PATHS))
        self.assertEqual(20, len(set(EXPECTED_W3_003_EDITABLE_PATHS)))
        self.assertEqual(
            EXPECTED_W3_003_EDITABLE_PATHS,
            EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS[-20:],
        )
        self.assertEqual(
            ("W3-05", "W3-08"),
            EXPECTED_RAG_LINKED_TRACKER_STEPS[
                EXPECTED_RAG_LINKED_TRACKER_STEPS.index(
                    "W3-05"
                ) : EXPECTED_RAG_LINKED_TRACKER_STEPS.index("W3-11")
            ],
        )
        self.assertIn("src/enterprise_ai_platform/guardrails", REQUIRED_DIRECTORIES)
        for path in EXPECTED_W3_003_EDITABLE_PATHS:
            self.assertIn(path, REQUIRED_FILES)
        for path in EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, EXPECTED_RAG_IMPLEMENTATION_PATHS)

    def test_w3_004_rollback_contract_is_exactly_appended(self) -> None:
        self.assertEqual(28, len(EXPECTED_W3_004_EDITABLE_PATHS))
        self.assertEqual(28, len(set(EXPECTED_W3_004_EDITABLE_PATHS)))
        self.assertEqual(
            EXPECTED_W3_004_EDITABLE_PATHS,
            EXPECTED_RAG_PRE_W7_001_IMPLEMENTATION_PATHS[-28:],
        )
        self.assertEqual(
            "W3-11",
            EXPECTED_RAG_LINKED_TRACKER_STEPS[EXPECTED_RAG_LINKED_TRACKER_STEPS.index("W3-11")],
        )
        self.assertIn("configs/rag/versions", REQUIRED_DIRECTORIES)
        self.assertIn(
            "src/enterprise_ai_platform/rag_rollback",
            REQUIRED_DIRECTORIES,
        )
        for path in EXPECTED_W3_004_EDITABLE_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w7_001_data_foundation_extends_rag_ownership(self) -> None:
        self.assertEqual(35, len(EXPECTED_W7_001_EDITABLE_PATHS))
        self.assertEqual(35, len(set(EXPECTED_W7_001_EDITABLE_PATHS)))
        self.assertEqual("W7-001", EXPECTED_RAG_LINKED_TRACKER_STEPS[-4])
        for path in EXPECTED_W7_001_EDITABLE_PATHS:
            self.assertIn(path, EXPECTED_RAG_IMPLEMENTATION_PATHS)

    def test_w7_002_processing_contract_extends_rag_ownership(self) -> None:
        self.assertEqual(18, len(EXPECTED_W7_002_EDITABLE_PATHS))
        self.assertEqual(18, len(set(EXPECTED_W7_002_EDITABLE_PATHS)))
        self.assertEqual("W7-002", EXPECTED_RAG_LINKED_TRACKER_STEPS[-3])
        for path in EXPECTED_W7_001_EDITABLE_PATHS:
            self.assertIn(path, EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS)
        self.assertIn("configs/processing", REQUIRED_DIRECTORIES)
        self.assertIn("src/enterprise_ai_platform/processing", REQUIRED_DIRECTORIES)
        for path in EXPECTED_W7_002_EDITABLE_PATHS:
            self.assertIn(path, REQUIRED_FILES)
            self.assertIn(path, EXPECTED_RAG_IMPLEMENTATION_PATHS)

    def test_w7_003_privacy_lifecycle_extends_rag_ownership(self) -> None:
        self.assertEqual(23, len(EXPECTED_W7_003_EDITABLE_PATHS))
        self.assertEqual(23, len(set(EXPECTED_W7_003_EDITABLE_PATHS)))
        self.assertEqual("W7-003", EXPECTED_RAG_LINKED_TRACKER_STEPS[-2])
        for path in EXPECTED_W7_002_EDITABLE_PATHS:
            self.assertIn(path, EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS)
        for path in EXPECTED_W7_003_EDITABLE_PATHS:
            self.assertIn(path, REQUIRED_FILES)
            self.assertIn(path, EXPECTED_RAG_IMPLEMENTATION_PATHS)

    def test_w3_002_evaluation_contract_is_exactly_appended(self) -> None:
        self.assertEqual(33, len(EXPECTED_EVAL_IMPLEMENTATION_PATHS))
        self.assertEqual(
            (
                ".gitignore",
                "configs/eval/cited-rag-evaluation-policy.yaml",
                "configs/eval/golden.jsonl",
            ),
            EXPECTED_EVAL_IMPLEMENTATION_PATHS[:3],
        )
        self.assertEqual(
            "tools/evaluationctl.py",
            EXPECTED_EVAL_IMPLEMENTATION_PATHS[25],
        )
        self.assertEqual(
            (
                "tests/feature/test_w2_002_embedder_contract.py",
                "tests/feature/test_w2_003_ingestion_contract.py",
            ),
            EXPECTED_EVAL_IMPLEMENTATION_PATHS[-2:],
        )
        self.assertEqual(
            ("W3-06", "W3-07", "W3-10"),
            EXPECTED_EVAL_LINKED_TRACKER_STEPS,
        )
        self.assertIn("src/enterprise_ai_platform/evaluation", REQUIRED_DIRECTORIES)
        for path in EXPECTED_EVAL_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w4_001_api_contract_is_exactly_appended(self) -> None:
        self.assertEqual(24, len(EXPECTED_API_IMPLEMENTATION_PATHS))
        self.assertEqual(24, len(set(EXPECTED_API_IMPLEMENTATION_PATHS)))
        self.assertEqual(
            (
                "src/enterprise_ai_platform/api/__init__.py",
                "src/enterprise_ai_platform/api/dependencies.py",
                "src/enterprise_ai_platform/api/errors.py",
                "src/enterprise_ai_platform/api/models.py",
                "src/enterprise_ai_platform/api/runtime.py",
                "src/enterprise_ai_platform/api/routes.py",
            ),
            EXPECTED_API_IMPLEMENTATION_PATHS[:6],
        )
        self.assertEqual(
            ("W4-01", "W4-02", "W4-10"),
            EXPECTED_API_LINKED_TRACKER_STEPS,
        )
        self.assertIn(
            "tests/feature/test_api_load_smoke.py",
            EXPECTED_API_IMPLEMENTATION_PATHS,
        )
        self.assertNotIn(
            "tests/feature/test_agent_failures.py",
            EXPECTED_API_IMPLEMENTATION_PATHS,
        )
        self.assertIn("src/enterprise_ai_platform/api", REQUIRED_DIRECTORIES)
        for path in EXPECTED_API_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w4_002_agent_contract_is_exactly_appended(self) -> None:
        self.assertEqual(41, len(EXPECTED_AGENT_IMPLEMENTATION_PATHS))
        self.assertEqual(41, len(set(EXPECTED_AGENT_IMPLEMENTATION_PATHS)))
        self.assertEqual(
            (
                "src/enterprise_ai_platform/agent/__init__.py",
                "src/enterprise_ai_platform/agent/authorization.py",
                "src/enterprise_ai_platform/agent/contracts.py",
            ),
            EXPECTED_AGENT_IMPLEMENTATION_PATHS[:3],
        )
        self.assertEqual(
            ("W4-03", "W4-04", "W4-05", "W4-06", "W4-07", "W4-09"),
            EXPECTED_AGENT_LINKED_TRACKER_STEPS,
        )
        self.assertIn(
            "tests/feature/test_agent_failures.py",
            EXPECTED_AGENT_IMPLEMENTATION_PATHS,
        )
        self.assertNotIn(
            "tests/feature/test_api_load_smoke.py",
            EXPECTED_AGENT_IMPLEMENTATION_PATHS,
        )
        self.assertIn("src/enterprise_ai_platform/agent", REQUIRED_DIRECTORIES)
        for path in EXPECTED_AGENT_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w11_001_observability_contract_is_exactly_appended(self) -> None:
        self.assertEqual(79, len(EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS))
        self.assertEqual(
            79,
            len(set(EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS)),
        )
        self.assertEqual(
            (
                "configs/observability/otel-collector.local.yaml",
                "src/enterprise_ai_platform/telemetry/__init__.py",
                "src/enterprise_ai_platform/telemetry/models.py",
                "src/enterprise_ai_platform/telemetry/runtime.py",
            ),
            EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS[:4],
        )
        self.assertEqual(
            [
                "W3-09",
                "W4-08",
                "W6-06",
                "W6-07",
                "W6-08",
                "W6-09",
                "W10-004",
                "W11-001",
            ],
            EXPECTED_FEATURES[5]["linked_tracker_steps"],
        )
        self.assertEqual(
            "tests/teardown/test_w11_001_ai_reliability_cleanliness.py",
            EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS[-1],
        )
        self.assertIn("configs/observability", REQUIRED_DIRECTORIES)
        self.assertIn(
            "src/enterprise_ai_platform/telemetry",
            REQUIRED_DIRECTORIES,
        )
        self.assertIn("configs/chaos", REQUIRED_DIRECTORIES)
        self.assertIn("observability/dashboards", REQUIRED_DIRECTORIES)
        for path in EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w4_011_release_contract_is_exactly_appended(self) -> None:
        self.assertEqual(29, len(EXPECTED_RELEASE_IMPLEMENTATION_PATHS))
        self.assertEqual(
            29,
            len(set(EXPECTED_RELEASE_IMPLEMENTATION_PATHS)),
        )
        self.assertEqual(
            (
                "configs/releases/versions/w4-known-good-v1.json",
                "configs/releases/versions/w4-synthetic-regression-v1.json",
                "src/enterprise_ai_platform/release_rollback/__init__.py",
            ),
            EXPECTED_RELEASE_IMPLEMENTATION_PATHS[:3],
        )
        self.assertEqual(
            ["W4-11"],
            EXPECTED_FEATURES[6]["linked_tracker_steps"],
        )
        self.assertIn("configs/releases/versions", REQUIRED_DIRECTORIES)
        self.assertIn(
            "src/enterprise_ai_platform/release_rollback",
            REQUIRED_DIRECTORIES,
        )
        for path in EXPECTED_RELEASE_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w1_08_security_controls_extend_the_repository_contract(self) -> None:
        self.assertEqual(
            (
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
            ),
            EXPECTED_W1_08_SECURITY_CONTROL_PATHS,
        )
        for path in EXPECTED_W1_08_SECURITY_CONTROL_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w5_004_lifecycle_extends_aws_ownership_exactly(self) -> None:
        self.assertEqual(96, len(EXPECTED_AWS_IMPLEMENTATION_PATHS))
        self.assertEqual(96, len(set(EXPECTED_AWS_IMPLEMENTATION_PATHS)))
        self.assertEqual(49, len(EXPECTED_W5_004_IMPLEMENTATION_PATHS))
        self.assertEqual(49, len(set(EXPECTED_W5_004_IMPLEMENTATION_PATHS)))
        self.assertEqual(5, len(EXPECTED_BEDROCK_IMPLEMENTATION_PATHS))
        self.assertEqual(5, len(set(EXPECTED_BEDROCK_IMPLEMENTATION_PATHS)))
        self.assertEqual(
            [
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
            EXPECTED_FEATURES[7]["linked_tracker_steps"],
        )
        self.assertEqual(["W5-02"], EXPECTED_FEATURES[8]["linked_tracker_steps"])
        self.assertIn("configs/verification", REQUIRED_DIRECTORIES)
        self.assertIn("policies/opa", REQUIRED_DIRECTORIES)
        for path in (*EXPECTED_AWS_IMPLEMENTATION_PATHS, *EXPECTED_BEDROCK_IMPLEMENTATION_PATHS):
            self.assertIn(path, REQUIRED_FILES)
        self.assertEqual(
            (
                "tools/platformctl/verify_clean.py",
                "tests/unit/test_platformctl_verify_clean.py",
                "tests/contract/test_platformctl_cli_contract.py",
                "tests/integration/test_platformctl_dry_run.py",
                "tests/feature/test_mvp_001_platformctl.py",
                "tests/smoke/test_platformctl_help.py",
                "tests/security/test_platformctl_approval_gates.py",
                "tests/security/test_repository_security.py",
            ),
            EXPECTED_AWS_IMPLEMENTATION_PATHS[-8:],
        )

    def test_w5_002_ci_feature_extends_repository_ownership_exactly(self) -> None:
        self.assertEqual(39, len(EXPECTED_GHA_IMPLEMENTATION_PATHS))
        self.assertEqual(39, len(set(EXPECTED_GHA_IMPLEMENTATION_PATHS)))
        self.assertEqual(["W5-07", "W5-08"], EXPECTED_FEATURES[9]["linked_tracker_steps"])
        self.assertEqual(
            (
                "requirements.txt",
                "src/enterprise_ai_platform/config.py",
                "src/enterprise_ai_platform/release_rollback/identity.py",
                "tests/unit/test_config.py",
                "tests/unit/test_release_rollback_identity.py",
                "tests/security/test_precommit_controls.py",
                "tests/teardown/test_w4_002_agent_cleanliness.py",
                "tests/teardown/test_w4_011_release_rollback_cleanliness.py",
            ),
            EXPECTED_GHA_IMPLEMENTATION_PATHS[-8:],
        )
        self.assertIn(".github/workflows", REQUIRED_DIRECTORIES)
        self.assertIn("configs/ci", REQUIRED_DIRECTORIES)
        for path in EXPECTED_GHA_IMPLEMENTATION_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_stale_or_custom_policy_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            opa_directory = root / "policies/opa"
            checkov_directory = root / "policies/checkov"
            opa_directory.mkdir(parents=True)
            checkov_directory.mkdir(parents=True)
            (opa_directory / "terraform.rego").write_text(
                "package stale\n", encoding="utf-8", newline="\n"
            )
            (opa_directory / "terraform_plan.rego").write_text(
                "package wrong.boundary\n", encoding="utf-8", newline="\n"
            )
            (opa_directory / "exceptions.json").write_text(
                '{"schema_version":"wrong","exceptions":[]}\n',
                encoding="utf-8",
                newline="\n",
            )
            (checkov_directory / "custom.py").write_text(
                "CUSTOM = True\n", encoding="utf-8", newline="\n"
            )

            errors = validate_repository(root)

        assert any("forbidden duplicate policy path" in error for error in errors)
        assert any("unexpected custom Checkov policy path" in error for error in errors)
        assert any("OPA policy package" in error for error in errors)
        assert any("policy exception schema_version" in error for error in errors)


def test_v2_configuration_keeps_historical_application_identity_separate() -> None:
    from tools.platformctl.lifecycle_io import load_lifecycle_config

    values = load_lifecycle_config(
        Path(__file__).resolve().parents[2] / "configs/lifecycle/w5-004.json"
    )
    assert values["schema_version"] == "w5-004.lifecycle.v2"
    assert values["lifecycle"]["identity_member_count"] == 385
    assert "source_composition_sha256" in values["repository"]


def test_w12_inventory_surfaces_are_explicit_and_versioned() -> None:
    from tools.platformctl.aws_inventory import W12_001_RESIDUAL_SURFACES

    assert len(W12_001_RESIDUAL_SURFACES) == len(set(W12_001_RESIDUAL_SURFACES))
    assert "codebuild-project-and-builds" in W12_001_RESIDUAL_SURFACES
    assert "eks-workload-probe-certificate-and-bundle" in W12_001_RESIDUAL_SURFACES


def test_retention_anchor_includes_lineage_timestamp() -> None:
    from datetime import UTC, datetime, timedelta

    from tools.capstone_release import retention_anchor_from_publication

    anchor, protected_until = retention_anchor_from_publication(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        "2026-01-01T00:00:02Z",
        "2026-01-01T00:00:03Z",
        now=datetime(2026, 1, 1, 0, 0, 4, tzinfo=UTC),
    )
    assert anchor == datetime(2026, 1, 1, 0, 0, 3, tzinfo=UTC)
    assert protected_until == anchor + timedelta(days=180)


def _w12_coverage_binding():
    from tools.capstone_release import _release_publication_key
    from tools.platformctl.lifecycle_models import (
        W12ProtectedObject,
        W12PublishedObject,
        W12RetentionBinding,
    )

    record_id = "123e4567-e89b-42d3-a456-426614174000"
    bucket = "synthetic-w12-bucket"
    version = "synthetic-version"
    stamp = "2026-01-01T00:00:00Z"
    record_key = _release_publication_key(record_id, "verified_record")
    sidecar_key = _release_publication_key(record_id, "verified_sidecar")
    lineage_key = _release_publication_key(record_id, "future_lineage")
    objects = (
        W12ProtectedObject(
            bucket, record_key, version, "a" * 64, "verified_record", "VERIFIED_SELF_PUBLICATION"
        ),
        W12ProtectedObject(
            bucket, sidecar_key, version, "b" * 64, "verified_sidecar", "VERIFIED_SELF_PUBLICATION"
        ),
        W12ProtectedObject(
            bucket, lineage_key, version, "c" * 64, "future_lineage", "VERIFIED_LINEAGE_DERIVATIVE"
        ),
    )
    return W12RetentionBinding(
        record_id=record_id,
        operation="deploy",
        verified_record_sha256="a" * 64,
        verified_created_at_utc=stamp,
        verified_record_object=W12PublishedObject(bucket, record_key, version, "a" * 64, stamp),
        verified_sidecar_object=W12PublishedObject(bucket, sidecar_key, version, "b" * 64, stamp),
        publication_anchor_utc=stamp,
        retain_until_utc="2026-06-30T00:00:00Z",
        kms_key_arn="arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
        protected_objects=tuple(
            sorted(
                objects,
                key=lambda obj: (
                    obj.bucket,
                    obj.key,
                    obj.version_id,
                ),
            )
        ),
    )


def test_verified_self_publication_exception() -> None:
    from dataclasses import replace

    from tools.platformctl.aws_inventory import validate_w12_binding_coverage
    from tools.platformctl.contracts import ContractError

    binding = _w12_coverage_binding()
    validate_w12_binding_coverage(binding)
    altered = tuple(
        replace(obj, coverage="R5_LOCATOR") if obj.evidence_kind == "verified_record" else obj
        for obj in binding.protected_objects
    )
    with unittest.TestCase().assertRaisesRegex(ContractError, "W12_SELF_PUBLICATION"):
        validate_w12_binding_coverage(replace(binding, protected_objects=altered))


def test_publication_anchor_uses_latest_verified_pair_timestamp() -> None:
    from datetime import UTC, datetime

    from tools.capstone_release import retention_anchor_from_publication

    anchor, _ = retention_anchor_from_publication(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:08Z",
        "2026-01-01T00:00:05Z",
        "2026-01-01T00:00:02Z",
        now=datetime(2026, 1, 1, 0, 0, 9, tzinfo=UTC),
    )
    assert anchor == datetime(2026, 1, 1, 0, 0, 8, tzinfo=UTC)


def test_w12_retention_unknown_is_indeterminate() -> None:
    from dataclasses import replace

    from tools.platformctl.aws_inventory import validate_w12_binding_coverage
    from tools.platformctl.contracts import ContractError

    binding = _w12_coverage_binding()
    incomplete = replace(
        binding,
        protected_objects=tuple(
            item for item in binding.protected_objects if item.evidence_kind != "future_lineage"
        ),
    )
    with unittest.TestCase().assertRaisesRegex(
        ContractError, "W12_PUBLICATION_COVERAGE_INCOMPLETE"
    ):
        validate_w12_binding_coverage(incomplete)


def test_purge_inventory_v2_rejected_for_w12_scope() -> None:
    from datetime import UTC, datetime

    from tools.platformctl.contracts import ContractError
    from tools.platformctl.destroy import _validate_w12_purge_scope
    from tools.platformctl.lifecycle_models import PurgeInventoryV2, PurgeItem

    inventory = PurgeInventoryV2(
        schema_version="w5-004.operation.v2",
        operation_id="synthetic",
        account_id="123456789012",
        region="ap-southeast-1",
        environment="sandbox",
        bucket="synthetic-w12-bucket",
        ownership="PROJECT_MANAGED",
        items=(PurgeItem("OBJECT_VERSION", "w12-001/source/source.zip", "v1"),),
        retained=(),
        pagination_evidence=None,
        observed_at="2026-01-01T00:00:00Z",
        valid_until="2026-01-02T00:00:00Z",
    )
    with unittest.TestCase().assertRaisesRegex(ContractError, "PURGE_V2_W12_SCOPE"):
        _validate_w12_purge_scope(inventory, (), datetime(2026, 1, 1, tzinfo=UTC))


def test_w12_retention_requires_canonical_verified_chain() -> None:
    from tools.capstone_release import ReleaseError, make_future_lineage_zip

    from tests.fakes.capstone_release import verified_release_chain

    chain = verified_release_chain()
    assert make_future_lineage_zip(chain)
    changed = [*chain]
    changed[3] = b"{}\n"
    with unittest.TestCase().assertRaises(ReleaseError):
        make_future_lineage_zip(changed)


def test_retention_expiry_does_not_authorize_purge() -> None:
    from datetime import UTC, datetime

    from tools.platformctl.contracts import ContractError
    from tools.platformctl.destroy import purge_approved_inventory

    with unittest.TestCase().assertRaisesRegex(ContractError, "VERIFIED_CONTEXT_AND_LEDGER"):
        purge_approved_inventory(None, None, None, datetime(2027, 1, 1, tzinfo=UTC))


def test_w12_lifecycle_diagnostic_classification() -> None:
    from tools.platformctl.aws_inventory import (
        W12_001_RESIDUAL_SURFACES,
        classify_w12_residuals,
    )

    empty = {name: [] for name in W12_001_RESIDUAL_SURFACES}
    assert classify_w12_residuals(empty) == "PASS_PHYSICALLY_ABSENT"
    assert classify_w12_residuals({**empty, W12_001_RESIDUAL_SURFACES[0]: None}) == "INDETERMINATE"
    assert (
        classify_w12_residuals({**empty, W12_001_RESIDUAL_SURFACES[0]: ["synthetic"]})
        == "RESIDUE_PRESENT"
    )
