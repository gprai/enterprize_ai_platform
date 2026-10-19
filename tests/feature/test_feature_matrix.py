"""Feature tests for the owner-approved feature matrix."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from tools.platformctl import validate as platform_validate
from tools.platformctl.cli import validate_feature_matrix
from tools.platformctl.validate import (
    EXPECTED_AGENT_IMPLEMENTATION_PATHS,
    EXPECTED_AGENT_LINKED_TRACKER_STEPS,
    EXPECTED_API_IMPLEMENTATION_PATHS,
    EXPECTED_API_LINKED_TRACKER_STEPS,
    EXPECTED_AWS_FEATURE,
    EXPECTED_AWS_IMPLEMENTATION_PATHS,
    EXPECTED_BEDROCK_FEATURE,
    EXPECTED_BEDROCK_IMPLEMENTATION_PATHS,
    EXPECTED_CAP_FEATURE,
    EXPECTED_CAP_IMPLEMENTATION_PATHS,
    EXPECTED_COST_004_FEATURE,
    EXPECTED_COST_004_IMPLEMENTATION_PATHS,
    EXPECTED_COST_005_FEATURE,
    EXPECTED_COST_005_IMPLEMENTATION_PATHS,
    EXPECTED_COST_006_FEATURE,
    EXPECTED_COST_006_IMPLEMENTATION_PATHS,
    EXPECTED_EVAL_002_FEATURE,
    EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    EXPECTED_EVAL_LINKED_TRACKER_STEPS,
    EXPECTED_GHA_002_FEATURE,
    EXPECTED_GHA_FEATURE,
    EXPECTED_GHA_IMPLEMENTATION_PATHS,
    EXPECTED_MLFLOW_FEATURE,
    EXPECTED_MLFLOW_IMPLEMENTATION_PATHS,
    EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS,
    EXPECTED_ORCH_FEATURE,
    EXPECTED_ORCH_IMPLEMENTATION_PATHS,
    EXPECTED_PRIV_003_FEATURE,
    EXPECTED_RAG_002_FEATURE,
    EXPECTED_RAG_003_FEATURE,
    EXPECTED_RAG_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_LINKED_TRACKER_STEPS,
    EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS,
    EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS,
    EXPECTED_REGISTRY_FEATURE,
    EXPECTED_REGISTRY_IMPLEMENTATION_PATHS,
    EXPECTED_RELEASE_IMPLEMENTATION_PATHS,
    EXPECTED_RET_003_FEATURE,
    EXPECTED_RET_003_IMPLEMENTATION_PATHS,
    EXPECTED_SERVE_FEATURE,
    EXPECTED_SERVE_IMPLEMENTATION_PATHS,
    EXPECTED_SUPPLY_002_FEATURE,
    EXPECTED_TRAIN_FEATURE,
    EXPECTED_TRAIN_IMPLEMENTATION_PATHS,
    EXPECTED_W3_003_EDITABLE_PATHS,
    EXPECTED_W3_004_EDITABLE_PATHS,
    EXPECTED_W6_003_IMPLEMENTATION_PATHS,
    EXPECTED_W6_004_IMPLEMENTATION_PATHS,
    EXPECTED_W7_001_EDITABLE_PATHS,
    EXPECTED_W7_002_EDITABLE_PATHS,
    EXPECTED_W7_003_EDITABLE_PATHS,
    EXPECTED_W9_004_IMPLEMENTATION_PATHS,
    EXPECTED_W10_001_IMPLEMENTATION_PATHS,
    EXPECTED_W10_002_IMPLEMENTATION_PATHS,
    EXPECTED_W10_003_IMPLEMENTATION_PATHS,
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
    "implementation_paths": list(EXPECTED_W6_003_IMPLEMENTATION_PATHS),
    "status": "In Progress",
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
EXPECTED_API_FEATURE = {
    "id": "API-001",
    "implementation_paths": list(EXPECTED_API_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_API_LINKED_TRACKER_STEPS),
}
EXPECTED_AGENT_FEATURE = {
    "id": "AGENT-001",
    "implementation_paths": list(EXPECTED_AGENT_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_AGENT_LINKED_TRACKER_STEPS),
}
EXPECTED_OBSERVABILITY_FEATURE = {
    "id": "OBS-001",
    "implementation_paths": list(EXPECTED_OBSERVABILITY_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": [
        "W3-09",
        "W4-08",
        "W6-06",
        "W6-07",
        "W6-08",
        "W6-09",
        "W10-004",
    ],
}
EXPECTED_RELEASE_FEATURE = {
    "id": "REL-001",
    "implementation_paths": list(EXPECTED_RELEASE_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": ["W4-11"],
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
            [
                EXPECTED_MVP_FEATURE,
                EXPECTED_RAG_FEATURE,
                EXPECTED_EVAL_FEATURE,
                EXPECTED_API_FEATURE,
                EXPECTED_AGENT_FEATURE,
                EXPECTED_OBSERVABILITY_FEATURE,
                EXPECTED_RELEASE_FEATURE,
                EXPECTED_AWS_FEATURE,
                EXPECTED_BEDROCK_FEATURE,
                EXPECTED_GHA_FEATURE,
                platform_validate.EXPECTED_EKS_FEATURE,
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
            ],
            matrix["features"],
        )

    def test_tracker_steps_are_links_not_feature_ids(self) -> None:
        matrix = read_matrix()
        features = matrix["features"]
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
            ],
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
        self.assertEqual(
            list(EXPECTED_API_LINKED_TRACKER_STEPS),
            features[3]["linked_tracker_steps"],
        )
        self.assertEqual(
            list(EXPECTED_AGENT_LINKED_TRACKER_STEPS),
            features[4]["linked_tracker_steps"],
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
            ],
            features[5]["linked_tracker_steps"],
        )
        self.assertEqual(["W4-11"], features[6]["linked_tracker_steps"])
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
            features[7]["linked_tracker_steps"],
        )
        self.assertEqual(["W5-02"], features[8]["linked_tracker_steps"])
        self.assertEqual(["W5-07", "W5-08"], features[9]["linked_tracker_steps"])
        self.assertEqual(
            ["W6-02", "W6-03", "W6-04", "W6-05", "W6-004"],
            features[10]["linked_tracker_steps"],
        )
        self.assertEqual(["W8-002"], features[11]["linked_tracker_steps"])
        self.assertEqual(["W8-003"], features[12]["linked_tracker_steps"])
        self.assertEqual(["W8-003"], features[13]["linked_tracker_steps"])
        self.assertEqual(["W8-004"], features[14]["linked_tracker_steps"])
        self.assertEqual(["W8-004"], features[15]["linked_tracker_steps"])
        self.assertEqual(["W10-001"], features[23]["linked_tracker_steps"])
        self.assertEqual(["W10-002"], features[24]["linked_tracker_steps"])
        self.assertEqual(["W10-003"], features[25]["linked_tracker_steps"])
        self.assertEqual(["W10-003"], features[26]["linked_tracker_steps"])

    def test_w8_002_paths_are_owned_by_the_serving_hardening_feature(self) -> None:
        feature = read_matrix()["features"][11]

        self.assertEqual(EXPECTED_SERVE_FEATURE, feature)
        self.assertEqual(35, len(EXPECTED_SERVE_IMPLEMENTATION_PATHS))
        self.assertEqual(35, len(set(EXPECTED_SERVE_IMPLEMENTATION_PATHS)))

    def test_w8_003_paths_are_owned_by_orchestration_and_cost_features(self) -> None:
        orch_feature, cost_feature = read_matrix()["features"][12:14]

        self.assertEqual(EXPECTED_ORCH_FEATURE, orch_feature)
        self.assertEqual(EXPECTED_COST_004_FEATURE, cost_feature)
        self.assertEqual(24, len(EXPECTED_ORCH_IMPLEMENTATION_PATHS))
        self.assertEqual(24, len(set(EXPECTED_ORCH_IMPLEMENTATION_PATHS)))
        self.assertEqual(14, len(EXPECTED_COST_004_IMPLEMENTATION_PATHS))
        self.assertEqual(14, len(set(EXPECTED_COST_004_IMPLEMENTATION_PATHS)))

    def test_w8_004_paths_are_owned_by_capacity_and_cost_features(self) -> None:
        capacity_feature, cost_feature = read_matrix()["features"][14:16]

        self.assertEqual(EXPECTED_CAP_FEATURE, capacity_feature)
        self.assertEqual(EXPECTED_COST_005_FEATURE, cost_feature)
        self.assertEqual(25, len(EXPECTED_CAP_IMPLEMENTATION_PATHS))
        self.assertEqual(25, len(set(EXPECTED_CAP_IMPLEMENTATION_PATHS)))
        self.assertEqual(20, len(EXPECTED_COST_005_IMPLEMENTATION_PATHS))
        self.assertEqual(20, len(set(EXPECTED_COST_005_IMPLEMENTATION_PATHS)))

    def test_w9_001_paths_are_owned_by_training_and_cost_features(self) -> None:
        training_feature, cost_feature = read_matrix()["features"][16:18]

        self.assertEqual(EXPECTED_TRAIN_FEATURE, training_feature)
        self.assertEqual(EXPECTED_COST_006_FEATURE, cost_feature)
        self.assertEqual(31, len(EXPECTED_TRAIN_IMPLEMENTATION_PATHS))
        self.assertEqual(31, len(set(EXPECTED_TRAIN_IMPLEMENTATION_PATHS)))
        self.assertEqual(20, len(EXPECTED_COST_006_IMPLEMENTATION_PATHS))
        self.assertEqual(20, len(set(EXPECTED_COST_006_IMPLEMENTATION_PATHS)))

    def test_w9_002_paths_are_owned_by_lineage_and_retention_features(self) -> None:
        lineage_feature, retention_feature = read_matrix()["features"][18:20]

        self.assertEqual(EXPECTED_MLFLOW_FEATURE, lineage_feature)
        self.assertEqual(EXPECTED_RET_003_FEATURE, retention_feature)
        self.assertEqual(27, len(EXPECTED_MLFLOW_IMPLEMENTATION_PATHS))
        self.assertEqual(27, len(set(EXPECTED_MLFLOW_IMPLEMENTATION_PATHS)))
        self.assertEqual(19, len(EXPECTED_RET_003_IMPLEMENTATION_PATHS))
        self.assertEqual(19, len(set(EXPECTED_RET_003_IMPLEMENTATION_PATHS)))

    def test_w9_003_paths_are_owned_by_model_registry_feature(self) -> None:
        registry_feature = read_matrix()["features"][20]

        self.assertEqual(EXPECTED_REGISTRY_FEATURE, registry_feature)
        self.assertEqual(27, len(EXPECTED_REGISTRY_IMPLEMENTATION_PATHS))
        self.assertEqual(27, len(set(EXPECTED_REGISTRY_IMPLEMENTATION_PATHS)))

    def test_w9_004_paths_are_owned_by_supply_chain_and_workflow_features(self) -> None:
        supply_feature, workflow_feature = read_matrix()["features"][21:23]

        self.assertEqual(EXPECTED_SUPPLY_002_FEATURE, supply_feature)
        self.assertEqual(EXPECTED_GHA_002_FEATURE, workflow_feature)
        self.assertEqual(32, len(EXPECTED_W9_004_IMPLEMENTATION_PATHS))
        self.assertEqual(32, len(set(EXPECTED_W9_004_IMPLEMENTATION_PATHS)))

    def test_w10_001_paths_are_owned_by_hybrid_retrieval_feature(self) -> None:
        hybrid_feature = read_matrix()["features"][-4]

        self.assertEqual(EXPECTED_RAG_002_FEATURE, hybrid_feature)
        self.assertEqual(23, len(EXPECTED_W10_001_IMPLEMENTATION_PATHS))
        self.assertEqual(23, len(set(EXPECTED_W10_001_IMPLEMENTATION_PATHS)))

    def test_w10_002_paths_are_owned_by_reranking_feature(self) -> None:
        reranking_feature = read_matrix()["features"][-3]

        self.assertEqual(EXPECTED_RAG_003_FEATURE, reranking_feature)
        self.assertEqual(29, len(EXPECTED_W10_002_IMPLEMENTATION_PATHS))
        self.assertEqual(29, len(set(EXPECTED_W10_002_IMPLEMENTATION_PATHS)))

    def test_w10_003_paths_are_owned_by_evaluation_and_privacy_features(self) -> None:
        evaluation_feature, privacy_feature = read_matrix()["features"][-2:]

        self.assertEqual(EXPECTED_EVAL_002_FEATURE, evaluation_feature)
        self.assertEqual(EXPECTED_PRIV_003_FEATURE, privacy_feature)
        self.assertEqual(21, len(EXPECTED_W10_003_IMPLEMENTATION_PATHS))
        self.assertEqual(21, len(set(EXPECTED_W10_003_IMPLEMENTATION_PATHS)))

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

    def test_w6_003_paths_are_owned_once_by_in_progress_mvp(self) -> None:
        matrix = read_matrix()
        mvp = matrix["features"][0]

        self.assertEqual(EXPECTED_MVP_FEATURE, mvp)
        self.assertEqual(20, len(mvp["implementation_paths"]))
        self.assertEqual(20, len(set(mvp["implementation_paths"])))
        self.assertNotIn("Done", [feature["status"] for feature in matrix["features"]])

    def test_cumulative_rag_contract_is_owned_only_by_rag_001(self) -> None:
        matrix = read_matrix()
        features = matrix["features"]
        (
            mvp_feature,
            rag_feature,
            eval_feature,
            api_feature,
            agent_feature,
            observability_feature,
            release_feature,
            aws_feature,
            bedrock_feature,
            gha_feature,
            eks_feature,
            serve_feature,
            orch_feature,
            cost_004_feature,
            capacity_feature,
            cost_005_feature,
            training_feature,
            cost_006_feature,
            mlflow_feature,
            ret_003_feature,
            registry_feature,
            supply_feature,
            gha_002_feature,
            rag_002_feature,
            rag_003_feature,
            eval_002_feature,
            priv_003_feature,
        ) = features

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
            ],
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
        self.assertEqual("AGENT-001", agent_feature["id"])
        self.assertTrue(
            set(EXPECTED_W6_004_IMPLEMENTATION_PATHS).issubset(eks_feature["implementation_paths"])
        )
        self.assertEqual("SERVE-002", serve_feature["id"])
        self.assertEqual("ORCH-001", orch_feature["id"])
        self.assertEqual("COST-004", cost_004_feature["id"])
        self.assertEqual("CAP-001", capacity_feature["id"])
        self.assertEqual("COST-005", cost_005_feature["id"])
        self.assertEqual("TRAIN-001", training_feature["id"])
        self.assertEqual("COST-006", cost_006_feature["id"])
        self.assertEqual("MLFLOW-001", mlflow_feature["id"])
        self.assertEqual("RET-003", ret_003_feature["id"])
        self.assertEqual("REGISTRY-001", registry_feature["id"])
        self.assertEqual("SUPPLY-002", supply_feature["id"])
        self.assertEqual("GHA-002", gha_002_feature["id"])
        self.assertEqual(EXPECTED_RAG_002_FEATURE, rag_002_feature)
        self.assertEqual(EXPECTED_RAG_003_FEATURE, rag_003_feature)
        self.assertEqual(EXPECTED_EVAL_002_FEATURE, eval_002_feature)
        self.assertEqual(EXPECTED_PRIV_003_FEATURE, priv_003_feature)
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
            rag_feature["linked_tracker_steps"][
                rag_feature["linked_tracker_steps"].index("W3-01") : rag_feature[
                    "linked_tracker_steps"
                ].index("W7-001")
            ],
        )
        self.assertEqual(
            list(EXPECTED_W3_003_EDITABLE_PATHS),
            list(EXPECTED_RAG_PRE_W3_004_IMPLEMENTATION_PATHS[-20:]),
        )
        self.assertEqual(
            list(EXPECTED_W3_004_EDITABLE_PATHS),
            [
                path
                for path in rag_feature["implementation_paths"]
                if path in EXPECTED_W3_004_EDITABLE_PATHS
            ],
        )
        self.assertEqual(
            len(rag_feature["implementation_paths"]),
            len(set(rag_feature["implementation_paths"])),
        )
        for path in EXPECTED_RAG_PRE_W3_003_IMPLEMENTATION_PATHS:
            self.assertIn(path, rag_feature["implementation_paths"])
        self.assertNotIn("W3-06", rag_feature["linked_tracker_steps"])
        self.assertEqual("W7-003", rag_feature["linked_tracker_steps"][-2])
        self.assertEqual("W7-004", rag_feature["linked_tracker_steps"][-1])
        self.assertTrue(
            set(EXPECTED_W7_001_EDITABLE_PATHS).issubset(rag_feature["implementation_paths"])
        )
        self.assertTrue(
            set(EXPECTED_W7_002_EDITABLE_PATHS).issubset(rag_feature["implementation_paths"])
        )
        self.assertTrue(
            set(EXPECTED_W7_003_EDITABLE_PATHS).issubset(rag_feature["implementation_paths"])
        )
        self.assertEqual("EVAL-001", eval_feature["id"])
        self.assertEqual("API-001", api_feature["id"])
        self.assertEqual("OBS-001", observability_feature["id"])
        self.assertEqual("REL-001", release_feature["id"])
        self.assertEqual("AWS-001", aws_feature["id"])
        self.assertEqual("BED-001", bedrock_feature["id"])
        self.assertEqual("GHA-001", gha_feature["id"])

    def test_rag_001_owns_the_exact_w7_002_processing_manifest(self) -> None:
        rag_feature = read_matrix()["features"][1]
        new_paths = [
            path
            for path in EXPECTED_W7_002_EDITABLE_PATHS
            if path not in EXPECTED_RAG_PRE_W7_002_IMPLEMENTATION_PATHS
        ]

        self.assertEqual("W7-002", rag_feature["linked_tracker_steps"][-3])
        self.assertEqual(
            new_paths,
            list(EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS[-len(new_paths) :]),
        )
        self.assertEqual(
            len(rag_feature["implementation_paths"]),
            len(set(rag_feature["implementation_paths"])),
        )

    def test_rag_001_owns_the_exact_w7_003_privacy_lifecycle_manifest(self) -> None:
        rag_feature = read_matrix()["features"][1]
        new_paths = [
            path
            for path in EXPECTED_W7_003_EDITABLE_PATHS
            if path not in EXPECTED_RAG_PRE_W7_003_IMPLEMENTATION_PATHS
        ]
        self.assertEqual("W7-003", rag_feature["linked_tracker_steps"][-2])
        self.assertEqual(
            new_paths,
            rag_feature["implementation_paths"][-len(new_paths) - 1 : -1],
        )

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
        misplaced_w2_004_step["features"][0]["linked_tracker_steps"].append("W2-09")
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

    def test_api_001_owns_w4_steps_and_only_current_column_l_paths(self) -> None:
        api_feature = read_matrix()["features"][3]

        self.assertEqual("API-001", api_feature["id"])
        self.assertEqual("In Progress", api_feature["status"])
        self.assertEqual(
            ["W4-01", "W4-02", "W4-10"],
            api_feature["linked_tracker_steps"],
        )
        self.assertEqual(
            list(EXPECTED_API_IMPLEMENTATION_PATHS),
            api_feature["implementation_paths"],
        )
        self.assertEqual(
            len(api_feature["implementation_paths"]),
            len(set(api_feature["implementation_paths"])),
        )
        self.assertEqual(24, len(api_feature["implementation_paths"]))
        self.assertIn(
            "tests/feature/test_api_load_smoke.py",
            api_feature["implementation_paths"],
        )
        self.assertNotIn(
            "tests/feature/test_agent_failures.py",
            api_feature["implementation_paths"],
        )

    def test_agent_001_owns_exact_steps_and_current_column_l_paths(self) -> None:
        agent_feature = read_matrix()["features"][4]

        self.assertEqual(EXPECTED_AGENT_FEATURE, agent_feature)
        self.assertEqual(
            ["W4-03", "W4-04", "W4-05", "W4-06", "W4-07", "W4-09"],
            agent_feature["linked_tracker_steps"],
        )
        self.assertEqual(41, len(agent_feature["implementation_paths"]))
        self.assertEqual(41, len(set(agent_feature["implementation_paths"])))
        self.assertIn(
            "tests/feature/test_agent_failures.py",
            agent_feature["implementation_paths"],
        )
        self.assertNotIn(
            "tests/feature/test_api_load_smoke.py",
            agent_feature["implementation_paths"],
        )

    def test_obs_001_owns_w4_003_and_w6_002_contracts(self) -> None:
        observability_feature = read_matrix()["features"][5]

        self.assertEqual(EXPECTED_OBSERVABILITY_FEATURE, observability_feature)
        self.assertEqual(68, len(observability_feature["implementation_paths"]))
        self.assertEqual(
            68,
            len(set(observability_feature["implementation_paths"])),
        )
        self.assertNotIn(
            "tests/feature/test_agent_failures.py",
            observability_feature["implementation_paths"],
        )
        self.assertNotIn(
            "tests/feature/test_api_load_smoke.py",
            observability_feature["implementation_paths"],
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
            ],
            observability_feature["linked_tracker_steps"],
        )
        self.assertEqual(
            "configs/observability/otel-collector.aws.yaml",
            observability_feature["implementation_paths"][32],
        )

    def test_rel_001_owns_only_w4_11_and_exact_column_l_paths(self) -> None:
        release_feature = read_matrix()["features"][6]

        self.assertEqual(EXPECTED_RELEASE_FEATURE, release_feature)
        self.assertEqual(["W4-11"], release_feature["linked_tracker_steps"])
        self.assertEqual(29, len(release_feature["implementation_paths"]))
        self.assertEqual(
            29,
            len(set(release_feature["implementation_paths"])),
        )
        self.assertEqual(
            list(EXPECTED_RELEASE_IMPLEMENTATION_PATHS),
            release_feature["implementation_paths"],
        )
        self.assertNotIn(
            "docs/rollback-records/W4-release.md",
            release_feature["implementation_paths"],
        )

    def test_w5_policy_pack_extends_only_aws_001(self) -> None:
        aws_feature = read_matrix()["features"][7]
        bedrock_feature = read_matrix()["features"][8]

        self.assertEqual(EXPECTED_AWS_FEATURE, aws_feature)
        self.assertEqual(EXPECTED_BEDROCK_FEATURE, bedrock_feature)
        self.assertEqual(96, len(EXPECTED_AWS_IMPLEMENTATION_PATHS))
        self.assertEqual(
            [
                "tools/platformctl/verify_clean.py",
                "tests/unit/test_platformctl_verify_clean.py",
                "tests/contract/test_platformctl_cli_contract.py",
                "tests/integration/test_platformctl_dry_run.py",
                "tests/feature/test_mvp_001_platformctl.py",
                "tests/smoke/test_platformctl_help.py",
                "tests/security/test_platformctl_approval_gates.py",
                "tests/security/test_repository_security.py",
            ],
            aws_feature["implementation_paths"][-8:],
        )
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
            aws_feature["linked_tracker_steps"],
        )
        self.assertEqual(5, len(EXPECTED_BEDROCK_IMPLEMENTATION_PATHS))
        self.assertTrue(
            set(EXPECTED_AWS_IMPLEMENTATION_PATHS).isdisjoint(EXPECTED_BEDROCK_IMPLEMENTATION_PATHS)
        )
        self.assertNotIn("W5-07", aws_feature["linked_tracker_steps"])

    def test_w5_002_ci_feature_owns_only_the_exact_phase_a_manifest(self) -> None:
        gha_feature = read_matrix()["features"][9]
        eks_feature = read_matrix()["features"][10]

        self.assertEqual(EXPECTED_GHA_FEATURE, gha_feature)
        self.assertEqual(platform_validate.EXPECTED_EKS_FEATURE, eks_feature)
        self.assertEqual(platform_validate.EXPECTED_EKS_FEATURE, eks_feature)
        self.assertEqual(39, len(EXPECTED_GHA_IMPLEMENTATION_PATHS))
        self.assertEqual(39, len(set(EXPECTED_GHA_IMPLEMENTATION_PATHS)))
        self.assertEqual(
            [
                "requirements.txt",
                "src/enterprise_ai_platform/config.py",
                "src/enterprise_ai_platform/release_rollback/identity.py",
                "tests/unit/test_config.py",
                "tests/unit/test_release_rollback_identity.py",
                "tests/security/test_precommit_controls.py",
                "tests/teardown/test_w4_002_agent_cleanliness.py",
                "tests/teardown/test_w4_011_release_rollback_cleanliness.py",
            ],
            gha_feature["implementation_paths"][-8:],
        )
        self.assertEqual(["W5-07", "W5-08"], gha_feature["linked_tracker_steps"])

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
