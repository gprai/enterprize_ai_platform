"""Contract for the governed W7-004 feature-management non-adoption decision."""

from pathlib import Path

from tools.platformctl.validate import load_feature_matrix

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_w7_004_is_owned_by_rag_without_a_feature_store_runtime() -> None:
    matrix = load_feature_matrix(REPOSITORY_ROOT / "feature-matrix.yaml")
    features = matrix["features"]
    rag_features = [feature for feature in features if feature["id"] == "RAG-001"]

    assert len(rag_features) == 1
    rag_feature = rag_features[0]
    tracker_steps = rag_feature["linked_tracker_steps"]
    implementation_paths = rag_feature["implementation_paths"]

    assert tracker_steps.count("W7-004") == 1
    assert tracker_steps[-1] == "W7-004"
    assert all(feature["id"] != "W7-004" for feature in features)
    assert "tests/contract/test_w7_004_feature_management_decision.py" in implementation_paths
    assert not any(
        any(
            token in path.casefold()
            for token in ("feature_store", "feature-store", "feast", "sagemaker")
        )
        for path in implementation_paths
    )
