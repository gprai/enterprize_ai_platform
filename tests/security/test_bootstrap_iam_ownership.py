"""The IAM migration preserves observed authority and has one state owner."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "infra/bootstrap"
CONFIG = BOOTSTRAP / "platform-iam-config"
HCP = json.loads((CONFIG / "hcp-resources.json").read_text(encoding="utf-8"))
BINDINGS = json.loads((CONFIG / "bindings.captured.json").read_text(encoding="utf-8"))


def render_captured_template(name: str) -> dict:
    text = (CONFIG / name).read_text(encoding="utf-8")
    for key, value in BINDINGS.items():
        text = text.replace("${" + key + "}", value)
    # Terraform template escapes preserve literal IAM policy variables.
    return json.loads(text.replace("$${", "${").replace("%%{", "%{"))


def import_blocks() -> list[tuple[str, str, str]]:
    source = (BOOTSTRAP / "platform_iam_imports.tf").read_text(encoding="utf-8")
    blocks = []
    for match in re.finditer(r"import\s*\{(?P<body>.*?)\n\}", source, re.DOTALL):
        body = match.group("body")
        destination = re.search(r"^\s*to\s*=\s*(.+)$", body, re.MULTILINE)
        identity = re.search(r'^\s*id\s*=\s*(".*")$', body, re.MULTILINE)
        assert destination and identity
        blocks.append((destination.group(1), json.loads(identity.group(1)), body))
    return blocks


def test_operational_manifest_and_imports_cover_all_adopted_iam_objects() -> None:
    blocks = import_blocks()
    assert len(HCP["roles"]) == 2
    assert len(HCP["policies"]) == 13
    assert len(HCP["inline_policies"]) == 4
    assert len(HCP["attachments"]) == 16
    assert len(blocks) == 66
    assert len({destination for destination, _, _ in blocks}) == 66
    assert len({identity for _, identity, _ in blocks}) == 66
    assert all("var.adopt_existing_platform_iam ?" in body for _, _, body in blocks)


def test_hcp_manifest_references_only_complete_renderable_policy_templates() -> None:
    expected_templates = {name + ".trust.json.tftpl" for name in HCP["roles"]}
    expected_templates.update(name + ".json.tftpl" for name in HCP["policies"])
    expected_templates.update(entry["file"] for entry in HCP["inline_policies"].values())
    assert {path.name for path in CONFIG.glob("*.tftpl")} == expected_templates
    for name in expected_templates:
        document = render_captured_template(name)
        assert document["Version"]
        assert document["Statement"]


def test_sandbox_forgets_only_relocated_objects_without_deleting_them() -> None:
    pattern = re.compile(
        r"removed\s*\{\s*from\s*=\s*(\S+)\s+lifecycle\s*\{\s*destroy\s*=\s*false\s*\}\s*\}"
    )
    observed = set()
    expected_counts = {"iam": 23, "eks": 4, "observability": 2}
    for module in (
        "iam",
        "eks",
        "observability",
    ):
        directory = ROOT / "infra/modules" / module
        source = (directory / "iam_ownership_transfer.tf").read_text(encoding="utf-8")
        entries = pattern.findall(source)
        assert len(entries) == source.count("removed {")
        assert len(entries) == expected_counts[module]
        observed.update(module + "." + address for address in entries)
        for file in directory.glob("*.tf"):
            assert not re.search(
                r'resource "aws_iam_(?:role|role_policy|role_policy_attachment)"',
                file.read_text(encoding="utf-8"),
            )
    assert len(observed) == 29


def test_imports_are_optional_and_never_target_aws_managed_policy_documents() -> None:
    source = (BOOTSTRAP / "platform_iam_imports.tf").read_text(encoding="utf-8")
    assert source.count("import {") == 66
    assert source.count("var.adopt_existing_platform_iam ?") == 66
    assert len(import_blocks()) == 66
    assert all(":iam::aws:" not in p["arn"] for p in HCP["policies"].values())


def test_bootstrap_owns_all_workload_roles_and_keeps_them_on_teardown() -> None:
    source = "\n".join(
        p.read_text(encoding="utf-8") for p in (BOOTSTRAP / "modules/platform-iam").glob("*.tf")
    )
    assert source.count('resource "aws_iam_role"') == 15
    assert source.count('resource "aws_iam_role_policy"') == 12
    assert source.count('resource "aws_iam_role_policy_attachment"') == 2  # node has three edges
    assert source.count("prevent_destroy = true") == 29
    root = (BOOTSTRAP / "platform_iam.tf").read_text(encoding="utf-8")
    assert root.count("prevent_destroy = true") == 4
    assert 'aws_iam_policy_attachment"' not in root
    assert 'resource "aws_iam_openid_connect_provider"' not in root
    assert 'resource "aws_iam_user"' not in root
    assert 'resource "aws_iam_access_key"' not in root


def test_generated_identity_bindings_cannot_widen_network_or_key_authority() -> None:
    documents = "\n".join(p.read_text(encoding="utf-8") for p in CONFIG.glob("*.tftpl"))
    assert not re.search(r"key/[a-f0-9-]{36}|/(vpc-|subnet-|sg-|rtb-)[a-f0-9]+", documents)
    defaults = (BOOTSTRAP / "platform_iam_variables.tf").read_text(encoding="utf-8")
    assert '"bootstrap_kms_key_arn"' not in defaults  # derived from the bootstrap resource
    assert '!can(regex("[\\"*?$]", v))' in defaults
    assert "sandbox_route_table_arn" in defaults
    assert "prevent_destroy" not in documents  # protection is in Terraform, not IAM JSON
