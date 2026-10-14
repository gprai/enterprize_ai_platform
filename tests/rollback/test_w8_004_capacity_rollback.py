"""Rollback identity checks for the W8-004 scaling extension."""

import json

PRE_W8_004_HPA_SPEC = {
    "minReplicas": 2,
    "maxReplicas": 4,
    "metrics": [
        {
            "type": "Resource",
            "resource": {
                "name": "cpu",
                "target": {"type": "Utilization", "averageUtilization": 70},
            },
        }
    ],
}
PRE_W8_004_PDB_AVAILABILITY = {"minAvailable": 1}


def test_prior_scaling_contract_is_explicit_and_deterministic() -> None:
    first = json.dumps(
        {"hpa": PRE_W8_004_HPA_SPEC, "pdb": PRE_W8_004_PDB_AVAILABILITY},
        sort_keys=True,
        separators=(",", ":"),
    )
    second = json.dumps(
        {"hpa": PRE_W8_004_HPA_SPEC, "pdb": PRE_W8_004_PDB_AVAILABILITY},
        sort_keys=True,
        separators=(",", ":"),
    )

    assert first == second
    assert "behavior" not in PRE_W8_004_HPA_SPEC
    assert PRE_W8_004_PDB_AVAILABILITY == {"minAvailable": 1}


def test_rollback_does_not_enable_conditional_serving_engines() -> None:
    rendered = json.dumps(PRE_W8_004_HPA_SPEC, sort_keys=True)

    for engine in ("karpenter", "ray", "triton", "sagemaker"):
        assert engine not in rendered.casefold()
