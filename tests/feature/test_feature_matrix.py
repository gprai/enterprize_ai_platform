"""Feature tests for the owner-approved feature matrix."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.platformctl.cli import validate_feature_matrix

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
    "status": "Not Started",
    "linked_tracker_steps": ["W2-03", "W2-01", "W2-02", "W2-04", "W2-08"],
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
            [EXPECTED_MVP_FEATURE, EXPECTED_RAG_FEATURE],
            matrix["features"],
        )

    def test_tracker_steps_are_links_not_feature_ids(self) -> None:
        matrix = read_matrix()
        features = matrix["features"]
        self.assertEqual(
            ["MVP-001", "RAG-001"],
            [feature["id"] for feature in features],
        )
        self.assertEqual(
            ["W1-03", "W1-04", "W1-07"],
            features[0]["linked_tracker_steps"],
        )
        self.assertEqual(
            ["W2-03", "W2-01", "W2-02", "W2-04", "W2-08"],
            features[1]["linked_tracker_steps"],
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


if __name__ == "__main__":
    unittest.main()
