"""Feature contract for cumulative W2-003 RAG ownership and starter fixtures."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from tools.platformctl.validate import (
    EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    validate_feature_matrix,
)

from enterprise_ai_platform.ingestion.models import (
    APPROVED_STARTER_ROWS,
    load_corpus_manifest,
    load_starter_fixture,
)

ROOT = Path(__file__).resolve().parents[2]
W2_003_IMPLEMENTATION_PATHS = (
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
)


def test_w2_003_paths_and_steps_are_owned_only_by_cumulative_rag_feature() -> None:
    matrix = json.loads((ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
    (
        mvp,
        rag,
        eval_feature,
        api_feature,
        agent_feature,
        obs_feature,
        release_feature,
        aws_feature,
        bedrock_feature,
        gha_feature,
        eks_feature,
        serve_feature,
        orch_feature,
        cost_feature,
        capacity_feature,
        capacity_cost_feature,
    ) = matrix["features"]

    assert [
        mvp["id"],
        rag["id"],
        eval_feature["id"],
        api_feature["id"],
        agent_feature["id"],
        obs_feature["id"],
        release_feature["id"],
        aws_feature["id"],
        bedrock_feature["id"],
        gha_feature["id"],
        eks_feature["id"],
        serve_feature["id"],
        orch_feature["id"],
        cost_feature["id"],
        capacity_feature["id"],
        capacity_cost_feature["id"],
    ] == [
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
    ]
    implementation_paths = rag["implementation_paths"]
    w2_003_start = implementation_paths.index(W2_003_IMPLEMENTATION_PATHS[0])
    w2_003_end = w2_003_start + len(W2_003_IMPLEMENTATION_PATHS)
    assert implementation_paths[w2_003_start:w2_003_end] == list(W2_003_IMPLEMENTATION_PATHS)
    assert implementation_paths[w2_003_end] == "docker-compose.w2-004.yml"
    assert all(implementation_paths.count(path) == 1 for path in W2_003_IMPLEMENTATION_PATHS)

    linked_steps = rag["linked_tracker_steps"]
    w2_003_step_start = linked_steps.index("W2-06")
    assert linked_steps[w2_003_step_start : w2_003_step_start + 2] == [
        "W2-06",
        "W2-07",
    ]
    assert linked_steps[w2_003_step_start + 2] == "W2-09"
    assert "W2-06" not in mvp["linked_tracker_steps"]
    assert "W2-07" not in mvp["linked_tracker_steps"]
    assert "src/enterprise_ai_platform/retrieval/models.py" in rag["implementation_paths"]
    assert "src/enterprise_ai_platform/embeddings/base.py" in rag["implementation_paths"]
    eval_paths = eval_feature["implementation_paths"]
    assert eval_paths == list(EXPECTED_EVAL_IMPLEMENTATION_PATHS)
    assert len(eval_paths) == len(set(eval_paths)) == 33
    assert eval_paths[25] == "tools/evaluationctl.py"
    assert matrix["features"][5]["linked_tracker_steps"][-4:] == [
        "W6-06",
        "W6-07",
        "W6-08",
        "W6-09",
    ]
    assert validate_feature_matrix(matrix) == []

    modified = deepcopy(matrix)
    modified["features"][1]["implementation_paths"].remove(
        "src/enterprise_ai_platform/ingestion/pipeline.py"
    )
    assert validate_feature_matrix(modified)


def test_approved_corpus_and_five_question_fixture_remain_exact() -> None:
    corpus = load_corpus_manifest(ROOT / "data" / "sample" / "corpus-manifest.json")
    questions = load_starter_fixture(ROOT / "configs" / "eval" / "w2-starter.jsonl")

    assert [source.source_id for source in corpus.documents] == [
        "DOC-SOT-V1.1",
        "DOC-COACHING-BLUEPRINT",
        "DOC-RESTRICTED-TEST",
    ]
    assert (
        tuple(
            (
                question.id,
                question.question,
                question.expected_source_ids,
                question.expected_facts,
                question.expected_outcome.value,
                question.safety_tags,
            )
            for question in questions
        )
        == APPROVED_STARTER_ROWS
    )
    assert all(question.tenant_id == "tenant-a" for question in questions)
    assert questions[-1].expected_source_ids == ()


def test_w7_governed_boundary_does_not_replace_w2_direct_ingestion() -> None:
    pipeline = (ROOT / "src/enterprise_ai_platform/ingestion/pipeline.py").read_text(
        encoding="utf-8"
    )
    governed = (ROOT / "src/enterprise_ai_platform/ingestion/workflow.py").read_text(
        encoding="utf-8"
    )
    assert "class IngestionPipeline" in pipeline
    assert "class GovernedIngestionWorkflow" in governed
    assert "EmbeddingEligibility" in governed
