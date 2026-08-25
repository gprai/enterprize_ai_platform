"""Contract tests for native YAML PII policy strictness."""

from pathlib import Path

import pytest

from enterprise_ai_platform.ingestion.errors import IngestionConfigurationError
from enterprise_ai_platform.ingestion.models import (
    QUARANTINE_ENTITY_TYPES,
    REDACTION_PLACEHOLDERS,
    load_pii_policy,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "configs" / "pii-policy.yaml"


def test_policy_uses_exact_quarantine_order_and_angle_bracket_placeholders() -> None:
    policy = load_pii_policy(POLICY_PATH)

    assert policy.quarantine_entities == QUARANTINE_ENTITY_TYPES
    assert tuple(
        (redaction.entity_type, redaction.placeholder)
        for redaction in policy.redactions
    ) == REDACTION_PLACEHOLDERS
    assert all(
        placeholder.startswith("<") and placeholder.endswith(">")
        for placeholder in policy.placeholder_by_entity.values()
    )


def test_duplicate_missing_reordered_unknown_and_modified_policy_is_rejected(
    tmp_path: Path,
) -> None:
    approved = POLICY_PATH.read_text(encoding="utf-8")
    first, second = "  - SG_NRIC_FIN\n", "  - PASSPORT_NUMBER\n"
    variants = (
        approved.replace(
            'schema_version: "1.0"',
            'schema_version: "1.0"\nschema_version: "1.0"',
            1,
        ),
        approved.replace("quarantine_entities:\n", "", 1),
        approved.replace(first + second, second + first, 1),
        approved + "unexpected: true\n",
        approved.replace('placeholder: "<PERSON>"', 'placeholder: "[PERSON]"', 1),
    )
    for index, content in enumerate(variants):
        candidate = tmp_path / f"invalid-policy-{index}.yaml"
        candidate.write_text(content, encoding="utf-8")
        with pytest.raises(IngestionConfigurationError):
            load_pii_policy(candidate)
