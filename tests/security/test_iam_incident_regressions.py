"""Independent capture fingerprints preserve every historical HCP repair and edge."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from tests.security.test_bootstrap_iam_ownership import HCP, render_captured_template

ROOT = Path(__file__).resolve().parents[2]
BASELINE = json.loads((ROOT / "tests/fixtures/iam_incident_baseline.json").read_bytes())
NETWORK = "enterprise-ai-capstone-hcp-apply-sandbox-network-bootstrap-v1.json.tftpl"


@pytest.mark.parametrize("name", sorted(BASELINE["documents"]))
def test_all_historical_hcp_permission_and_trust_repairs_are_preserved(name: str) -> None:
    document = render_captured_template(name)
    if name == NETWORK:
        # The only approved semantic change is stricter initial default-SG tagging.
        c = document["Statement"][1]["Condition"]
        c["StringEquals"] = {"ec2:Region": c["StringEquals"]["ec2:Region"]}
        del c["ForAllValues:StringEquals"]
    actual = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert actual == BASELINE["documents"][name]


@pytest.mark.parametrize("role", sorted(BASELINE["attachments"]))
def test_every_plan_and_apply_attachment_matches_capture(role: str) -> None:
    assert (
        sorted(v["policy"] for v in HCP["attachments"].values() if v["role"] == role)
        == BASELINE["attachments"][role]
    )


def permits_tags(tags: dict[str, str]) -> bool:
    condition = render_captured_template(NETWORK)["Statement"][1]["Condition"]
    required = {
        k.removeprefix("aws:RequestTag/"): v
        for k, v in condition["StringEquals"].items()
        if k.startswith("aws:RequestTag/")
    }
    return all(tags.get(k) == v for k, v in required.items()) and set(tags) <= set(
        condition["ForAllValues:StringEquals"]["aws:TagKeys"]
    )


def test_default_sg_tag_conditions_reject_missing_wrong_and_extra_tags() -> None:
    statement = render_captured_template(NETWORK)["Statement"][1]
    tags = {
        k.removeprefix("aws:RequestTag/"): v
        for k, v in statement["Condition"]["StringEquals"].items()
        if k.startswith("aws:RequestTag/")
    }
    assert len(tags) == 9 and permits_tags(tags)
    assert statement["Resource"].startswith(
        "arn:aws:ec2:ap-southeast-1:526338061652:security-group/sg-"
    )
    assert statement["Condition"]["ArnEquals"]["ec2:Vpc"].startswith(
        "arn:aws:ec2:ap-southeast-1:526338061652:vpc/vpc-"
    )
    for key in tags:
        missing = deepcopy(tags)
        del missing[key]
        assert not permits_tags(missing)
        assert not permits_tags(dict(tags, **{key: "wrong"}))
    assert not permits_tags(dict(tags, Unapproved="value"))


def test_workload_identity_and_complementary_key_controls_remain() -> None:
    module = ROOT / "infra/bootstrap/modules/platform-iam"
    source = (module / "main.tf").read_text()
    public = (module / "w12_prerequisite_images.tf").read_text()
    foundation = (module / "foundation.tf").read_text()
    assert "sts:GetServiceBearerToken" in public and "sts:AWSServiceName" not in public
    assert "repository_subject" in source and "github_repository_id" in source
    for policy in (
        "AmazonEKSClusterPolicy",
        "AmazonEKSWorkerNodePolicy",
        "AmazonEKS_CNI_Policy",
        "AmazonEC2ContainerRegistryPullOnly",
    ):
        assert policy in foundation
    kms = (ROOT / "infra/modules/kms/main.tf").read_text()
    assert "kms:RetireGrant" in kms and "kms:CreateGrant" in kms
    bootstrap = (ROOT / "infra/bootstrap/main.tf").read_text()
    assert "AllowExactAccountDynamoDBStateGrant" in bootstrap
    assert "kms:CreateGrant" in bootstrap
