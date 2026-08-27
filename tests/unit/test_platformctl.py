"""Unit tests for the read-only platformctl contract."""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path

from tools.platformctl import __version__
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
    EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    EXPECTED_EVAL_LINKED_TRACKER_STEPS,
    EXPECTED_RAG_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_LINKED_TRACKER_STEPS,
    EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS,
    EXPECTED_W3_003_EDITABLE_PATHS,
    EXPECTED_W3_004_EDITABLE_PATHS,
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
        self.assertEqual("0.1.0", __version__)

    def test_parser_exposes_w1_004_lifecycle_subcommands(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["validate"])
        self.assertEqual("validate", arguments.command)
        help_text = parser.format_help()
        for command in (
            "bootstrap",
            "plan",
            "deploy",
            "validate",
            "rollback",
            "destroy",
            "verify-clean",
        ):
            self.assertIn(command, help_text)
        self.assertNotIn("--execute", help_text)

    def test_approved_matrix_has_no_errors(self) -> None:
        self.assertIs(EXPECTED_FEATURE, EXPECTED_FEATURES[0])
        self.assertEqual(
            ["MVP-001", "RAG-001", "EVAL-001"],
            [feature["id"] for feature in EXPECTED_FEATURES],
        )
        self.assertEqual([], validate_feature_matrix(approved_matrix()))

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
        self.assertTrue(
            any("owner-approved ordered feature set" in error for error in errors)
        )

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

        self.assertTrue(
            set(expected_w3_paths).issubset(EXPECTED_RAG_IMPLEMENTATION_PATHS)
        )
        for path in expected_w3_paths:
            self.assertEqual(1, EXPECTED_RAG_IMPLEMENTATION_PATHS.count(path))
        self.assertEqual(
            ("W3-01", "W3-02", "W3-03", "W3-04"),
            EXPECTED_RAG_LINKED_TRACKER_STEPS[-7:-3],
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
            EXPECTED_RAG_LINKED_TRACKER_STEPS[-3:-1],
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
            EXPECTED_RAG_IMPLEMENTATION_PATHS[-28:],
        )
        self.assertEqual("W3-11", EXPECTED_RAG_LINKED_TRACKER_STEPS[-1])
        self.assertIn("configs/rag/versions", REQUIRED_DIRECTORIES)
        self.assertIn(
            "src/enterprise_ai_platform/rag_rollback",
            REQUIRED_DIRECTORIES,
        )
        for path in EXPECTED_W3_004_EDITABLE_PATHS:
            self.assertIn(path, REQUIRED_FILES)

    def test_w3_002_evaluation_contract_is_exactly_appended(self) -> None:
        self.assertEqual(33, len(EXPECTED_EVAL_IMPLEMENTATION_PATHS))
        self.assertEqual(
            (
                ".gitignore",
                "configs/eval/w3-002.yaml",
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
