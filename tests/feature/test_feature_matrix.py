"""Feature tests for the owner-approved feature matrix."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from tools.platformctl.cli import validate_feature_matrix
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

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPOSITORY_ROOT / "feature-matrix.yaml"

EXPECTED_PROJECT = {
    "name": "enterprise-ai-platform",
    "owner": "Gyan Prakash Rai",
    "default_environment": "sandbox",
    "cost_center": "ai_platform_learn",
    "repository": "https://github.com/gprai/enterprize_ai_platform",
    "expires_at": "31/12/2026",
}
EXPECTED_STATUSES = [
    "Not Started",
    "In Progress",
    "Blocked",
    "Ready for Review",
    "Done",
    "Deferred",
]
EXPECTED_MVP_FEATURE = {
    "id": "MVP-001",
    "status": "Not Started",
    "linked_tracker_steps": ["W1-03", "W1-04", "W1-07"],
}
EXPECTED_RAG_FEATURE = {
    "id": "RAG-001",
    "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
}
EXPECTED_EVAL_FEATURE = {
    "id": "EVAL-001",
    "implementation_paths": list(EXPECTED_EVAL_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_EVAL_LINKED_TRACKER_STEPS),
}


def read_matrix() -> dict[str, object]:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


class FeatureMatrixTests(unittest.TestCase):
    def test_matrix_uses_exact_owner_values(self) -> None:
        matrix = read_matrix()
        self.assertEqual("1.0", matrix["schema_version"])
        self.assertEqual(EXPECTED_PROJECT, matrix["project"])
        self.assertEqual(EXPECTED_STATUSES, matrix["permitted_statuses"])
        self.assertEqual(
            [EXPECTED_MVP_FEATURE, EXPECTED_RAG_FEATURE, EXPECTED_EVAL_FEATURE],
            matrix["features"],
        )

    def test_tracker_steps_are_links_not_feature_ids(self) -> None:
        matrix = read_matrix()
        features = matrix["features"]
        self.assertEqual(
            ["MVP-001", "RAG-001", "EVAL-001"],
            [feature["id"] for feature in features],
        )
        self.assertEqual(
            ["W1-03", "W1-04", "W1-07"],
            features[0]["linked_tracker_steps"],
        )
        self.assertEqual(
            list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
            features[1]["linked_tracker_steps"],
        )
        self.assertEqual(
            list(EXPECTED_EVAL_LINKED_TRACKER_STEPS),
            features[2]["linked_tracker_steps"],
        )

    def test_unapproved_feature_or_status_fails_contract(self) -> None:
        matrix = read_matrix()
        matrix["features"] = [
            EXPECTED_MVP_FEATURE,
            {
                "id": "RAG-001",
                "status": "Complete",
                "linked_tracker_steps": [],
            },
        ]
        self.assertTrue(validate_feature_matrix(matrix))

    def test_cumulative_rag_contract_is_owned_only_by_rag_001(self) -> None:
        matrix = read_matrix()
        features = matrix["features"]
        mvp_feature, rag_feature, eval_feature = features

        self.assertEqual(
            ["MVP-001", "RAG-001", "EVAL-001"],
            [item["id"] for item in features],
        )
        for step in ("W2-05", "W2-06", "W2-07", "W2-09", "W2-10"):
            self.assertNotIn(step, mvp_feature["linked_tracker_steps"])
        self.assertEqual(
            list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
            rag_feature["linked_tracker_steps"],
        )
        self.assertEqual(
            list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
            rag_feature["implementation_paths"],
        )
        self.assertEqual(
            [
                "W3-01",
                "W3-02",
                "W3-03",
                "W3-04",
                "W3-05",
                "W3-08",
                "W3-11",
            ],
            rag_feature["linked_tracker_steps"][-7:],
        )
        self.assertEqual(
            list(EXPECTED_W3_003_EDITABLE_PATHS),
            list(EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS[-20:]),
        )
        self.assertEqual(
            list(EXPECTED_W3_004_EDITABLE_PATHS),
            rag_feature["implementation_paths"][-28:],
        )
        self.assertEqual(
            len(rag_feature["implementation_paths"]),
            len(set(rag_feature["implementation_paths"])),
        )
        for path in EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, rag_feature["implementation_paths"])
        self.assertNotIn("W3-06", rag_feature["linked_tracker_steps"])
        self.assertEqual("EVAL-001", eval_feature["id"])

    def test_eval_001_owns_the_exact_w3_002_manifest(self) -> None:
        matrix = read_matrix()
        eval_feature = matrix["features"][2]

        self.assertEqual(
            list(EXPECTED_EVAL_IMPLEMENTATION_PATHS),
            eval_feature["implementation_paths"],
        )
        self.assertEqual(33, len(eval_feature["implementation_paths"]))
        self.assertEqual(
            33,
            len(set(eval_feature["implementation_paths"])),
        )
        self.assertEqual(
            "tools/evaluationctl.py",
            eval_feature["implementation_paths"][25],
        )
        self.assertEqual(
            ["W3-06", "W3-07", "W3-10"],
            eval_feature["linked_tracker_steps"],
        )

    def test_missing_duplicate_reordered_or_misplaced_contract_is_rejected(
        self,
    ) -> None:
        variants: list[dict[str, object]] = []

        missing_step = deepcopy(read_matrix())
        missing_step["features"][1]["linked_tracker_steps"].remove("W2-07")
        variants.append(missing_step)

        duplicate_step = deepcopy(read_matrix())
        duplicate_step["features"][1]["linked_tracker_steps"].append("W2-07")
        variants.append(duplicate_step)

        misplaced_w2_004_step = deepcopy(read_matrix())
        misplaced_w2_004_step["features"][0]["linked_tracker_steps"].append(
            "W2-09"
        )
        variants.append(misplaced_w2_004_step)

        reordered_paths = deepcopy(read_matrix())
        reordered_paths["features"][1]["implementation_paths"].reverse()
        variants.append(reordered_paths)

        duplicate_path = deepcopy(read_matrix())
        duplicate_path["features"][1]["implementation_paths"].append(
            "src/enterprise_ai_platform/ingestion/pipeline.py"
        )
        variants.append(duplicate_path)

        misplaced_step = deepcopy(read_matrix())
        misplaced_step["features"][0]["linked_tracker_steps"].append("W2-05")
        variants.append(misplaced_step)

        additional_feature = deepcopy(read_matrix())
        additional_feature["features"].append(
            {
                "id": "UNAPPROVED-001",
                "status": "Not Started",
                "linked_tracker_steps": ["W2-05"],
                "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
            }
        )
        variants.append(additional_feature)

        for variant in variants:
            with self.subTest(variant=variant):
                self.assertTrue(validate_feature_matrix(variant))

    def test_trailing_content_is_rejected_as_malformed_json(self) -> None:
        valid_text = MATRIX_PATH.read_text(encoding="utf-8")

        with self.assertRaises(json.JSONDecodeError):
            json.loads(valid_text + "\ntrailing-content")

    def test_duplicate_json_key_is_rejected_by_repository_loader(self) -> None:
        from tools.platformctl.validate import MatrixValidationError, load_feature_matrix

        with tempfile.TemporaryDirectory() as temporary_directory:
            duplicate = Path(temporary_directory) / "feature-matrix-duplicate-test.json"
            duplicate.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}',
                encoding="utf-8",
            )
            with self.assertRaises(MatrixValidationError):
                load_feature_matrix(duplicate)
