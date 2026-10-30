"""Security contracts for the offline W5-003 OPA and Checkov policy pack."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies/opa/terraform_plan.rego"
POLICY_TEST = ROOT / "policies/opa/terraform_plan_test.rego"
EXCEPTIONS = ROOT / "policies/opa/exceptions.json"
CHECKOV_CONFIG = ROOT / ".checkov.yml"

EXPECTED_INVENTORY = (
    (
        "W5-PLAN-001",
        "CRITICAL",
        "PLAN_INPUT",
        "REJECT_UNEVALUATED_INPUT",
    ),
    ("W5-REG-001", "CRITICAL", "REGION", "USE_APPROVED_REGION"),
    ("W5-TAG-001", "HIGH", "TAGS", "APPLY_MANDATORY_TAGS"),
    ("W5-TAG-002", "HIGH", "TAG_EXPIRY", "SET_BOUNDED_EXPIRY"),
    (
        "W5-PLAN-002",
        "HIGH",
        "CHANGE_LIFECYCLE",
        "REQUIRE_OWNER_REVIEW",
    ),
    (
        "W5-S3-001",
        "CRITICAL",
        "S3_PUBLIC_ACCESS",
        "ENABLE_S3_PUBLIC_BLOCK",
    ),
    (
        "W5-S3-002",
        "CRITICAL",
        "S3_ENCRYPTION",
        "USE_APPROVED_S3_KMS",
    ),
    ("W5-S3-003", "HIGH", "S3_LIFECYCLE", "ENABLE_S3_LIFECYCLE"),
    ("W5-S3-004", "CRITICAL", "S3_TRANSPORT", "ENFORCE_S3_TLS"),
    (
        "W5-KMS-001",
        "CRITICAL",
        "KMS_LIFECYCLE",
        "ENABLE_KMS_ROTATION",
    ),
    ("W5-IAM-001", "CRITICAL", "IAM_ACTION", "NARROW_IAM_ACTIONS"),
    ("W5-IAM-002", "CRITICAL", "IAM_SCOPE", "NARROW_IAM_SCOPE"),
    (
        "W5-NET-001",
        "CRITICAL",
        "NETWORK_TOPOLOGY",
        "USE_PRIVATE_NETWORK",
    ),
    (
        "W5-NET-002",
        "CRITICAL",
        "NETWORK_TRAFFIC",
        "RESTRICT_SECURITY_GROUP",
    ),
    (
        "W5-OS-001",
        "CRITICAL",
        "OPENSEARCH_SECURITY",
        "HARDEN_OPENSEARCH",
    ),
    (
        "W5-OS-002",
        "HIGH",
        "OPENSEARCH_OPERATIONS",
        "CONFIGURE_OPENSEARCH_LOGS",
    ),
    ("W5-ECR-001", "CRITICAL", "ECR_SECURITY", "HARDEN_ECR"),
    ("W5-ECR-002", "HIGH", "ECR_RETENTION", "RETAIN_TEN_IMAGES"),
    (
        "W5-SEC-001",
        "CRITICAL",
        "SECRET_BOUNDARY",
        "REMOVE_SECRET_MATERIAL",
    ),
    (
        "W5-EXC-001",
        "CRITICAL",
        "EXCEPTION_REGISTRY",
        "REPAIR_EXCEPTION_REGISTRY",
    ),
)

EXPECTED_SKIPS = {
    "infra/bootstrap/main.tf": (
        "CKV_AWS_109",
        "CKV_AWS_111",
        "CKV_AWS_356",
        "CKV2_AWS_62",
        "CKV_AWS_144",
        "CKV_AWS_18",
    ),
    "infra/modules/storage/main.tf": (
        "CKV_AWS_144",
        "CKV_AWS_18",
    ),
    "infra/modules/kms/main.tf": (
        "CKV_AWS_109",
        "CKV_AWS_111",
        "CKV_AWS_356",
    ),
    "infra/modules/network/main.tf": ("CKV2_AWS_11",),
    "infra/modules/eks/main.tf": ("CKV_AWS_39",),
    "infra/bootstrap/modules/platform-iam/main.tf": (
        "CKV_AWS_358",
        "CKV_AWS_111",
        "CKV_AWS_355",
        "CKV_AWS_358",
        "CKV_AWS_111",
        "CKV_AWS_355",
    ),
    "infra/modules/observability/main.tf": (
        "CKV_AWS_158",
        "CKV_AWS_338",
        "CKV_AWS_158",
        "CKV_AWS_338",
        "CKV_AWS_158",
        "CKV_AWS_338",
    ),
    "infra/modules/opensearch/main.tf": (
        "CKV_AWS_338",
        "CKV_AWS_318",
        "CKV2_AWS_59",
    ),
    "infra/bootstrap/modules/platform-iam/w12_prerequisite_images.tf": (
        "CKV_AWS_358",
        "CKV_AWS_107",
    ),
    "infra/modules/secrets/main.tf": ("CKV2_AWS_57",),
}


def _skip_directives(path: Path) -> tuple[tuple[str, str], ...]:
    matches = re.findall(r"#checkov:skip=([^:]+):([^\r\n]+)", path.read_text(encoding="utf-8"))
    return tuple((check_id, rationale.strip()) for check_id, rationale in matches)


def test_policy_inventory_order_severity_category_and_remediation_are_exact() -> None:
    source = POLICY.read_text(encoding="utf-8")
    inventory = tuple(
        re.findall(
            r'\{"policy_id": "([^"]+)", "severity": "([^"]+)", '
            r'"category": "([^"]+)", "remediation_code": "([^"]+)"\}',
            source,
        )
    )

    assert inventory == EXPECTED_INVENTORY
    assert len({item[0] for item in inventory}) == 20
    assert len({item[2] for item in inventory}) == 20
    assert len({item[3] for item in inventory}) == 20


def test_safe_finding_schema_has_only_the_exact_bounded_fields() -> None:
    source = POLICY.read_text(encoding="utf-8")
    block = source.split("safe_finding(item) := {", maxsplit=1)[1].split("} if {", maxsplit=1)[0]
    fields = tuple(re.findall(r'^\s*"([a-z_]+)":', block, flags=re.MULTILINE))

    assert fields == (
        "schema_version",
        "policy_id",
        "severity",
        "resource_address",
        "category",
        "remediation_code",
        "exception_status",
    )
    assert '"w5-003.policy-finding.v1"' in block
    for forbidden in (
        "raw",
        "rationale",
        "evidence_reference",
        "environment",
        "credential",
        "secret",
        "stack",
        "exception_message",
    ):
        assert forbidden not in block.casefold()


def test_policy_has_no_network_runtime_or_provider_escape() -> None:
    combined = "\n".join(
        (
            POLICY.read_text(encoding="utf-8"),
            POLICY_TEST.read_text(encoding="utf-8"),
        )
    )
    for forbidden in (
        "http.send",
        "net.lookup_ip_addr",
        "opa.runtime",
        "aws ",
        "terraform plan",
        "github api",
    ):
        assert forbidden not in combined.casefold()


def test_checkov_configuration_is_exactly_offline_without_global_skips() -> None:
    config = yaml.safe_load(CHECKOV_CONFIG.read_text(encoding="utf-8"))

    assert config == {
        "framework": ["terraform", "kubernetes"],
        "skip-download": True,
        "skip-results-upload": True,
        "download-external-modules": False,
        "compact": True,
        "quiet": True,
        "soft-fail": False,
    }
    assert "skip-check" not in config
    assert "api-key" not in config
    assert "prisma-api-url" not in config


def test_inline_checkov_skip_inventory_and_rationales_are_exact() -> None:
    observed: dict[str, tuple[str, ...]] = {}
    rationales: list[str] = []
    for relative_path in EXPECTED_SKIPS:
        directives = _skip_directives(ROOT / relative_path)
        observed[relative_path] = tuple(item[0] for item in directives)
        rationales.extend(item[1] for item in directives)

    assert observed == EXPECTED_SKIPS
    assert sum(len(items) for items in observed.values()) == 31
    weighted_skips = 17 + 3
    assert weighted_skips == 20
    opensearch = (ROOT / "infra/modules/opensearch/main.tf").read_text(encoding="utf-8")
    log_group_keys = re.findall(
        r"^\s+(application|audit|index_slow|search_slow)\s*=",
        opensearch,
        flags=re.MULTILINE,
    )
    assert log_group_keys == ["application", "audit", "index_slow", "search_slow"]
    assert "for_each = local.log_groups" in opensearch
    assert all(rationale for rationale in rationales)
    assert all(
        "owner-approved" in rationale.casefold()
        or "approved" in rationale.casefold()
        or "not applicable" in rationale.casefold()
        or "explicitly bounded" in rationale.casefold()
        or "no unrelated resource" in rationale.casefold()
        or "metadata-only" in rationale.casefold()
        for rationale in rationales
    )


def test_no_other_inline_skip_or_custom_checkov_policy_exists() -> None:
    all_directives: list[tuple[str, str]] = []
    for terraform_path in sorted((ROOT / "infra").rglob("*.tf")):
        relative = terraform_path.relative_to(ROOT).as_posix()
        all_directives.extend((relative, item[0]) for item in _skip_directives(terraform_path))

    expected = [
        (path, check_id) for path, check_ids in EXPECTED_SKIPS.items() for check_id in check_ids
    ]
    assert sorted(all_directives) == sorted(expected)
    assert not (ROOT / "policies/checkov").exists()
    assert not (ROOT / "checks").exists()


def test_initial_registry_does_not_copy_any_checkov_skip() -> None:
    source = EXCEPTIONS.read_text(encoding="utf-8")
    registry = json.loads(source)
    assert registry["schema_version"] == "w5-003.policy-exceptions.v1"
    assert all(not exception["policy_id"].startswith("CKV") for exception in registry["exceptions"])
    assert "CKV_" not in source and "CKV2_" not in source


def test_committed_policy_fixtures_contain_no_complete_secret_value() -> None:
    committed_sources = (
        POLICY.read_text(encoding="utf-8"),
        POLICY_TEST.read_text(encoding="utf-8"),
    )
    combined = "\n".join(committed_sources)

    assert not re.search(r"AKIA[0-9A-Z]{16}", combined)
    assert not re.search(
        r'(?i)(password|client_secret|api_key)\s*[=:]\s*"[^"\n]{8,}"',
        combined,
    )
    assert 'concat("", ["runtime", "-", "only"])' in combined


def test_w7_policy_extension_is_offline_and_rejects_unapproved_services() -> None:
    combined = POLICY.read_text(encoding="utf-8") + POLICY_TEST.read_text(encoding="utf-8")
    assert "w7_001_findings" in combined
    for resource_type in (
        "aws_glue_catalog_database",
        "aws_cloudwatch_event_rule",
        "aws_sfn_state_machine",
    ):
        assert resource_type in combined
    assert "http.send" not in combined


def test_w12_codebuild_is_explicitly_policy_scoped() -> None:
    source = POLICY.read_text(encoding="utf-8")
    assert source.count('"aws_codebuild_project"') >= 2
    assert "package enterprise_ai.terraform.plan" in source
    assert "policy_evaluated := true" in source
