"""Security contracts for the W1-08 local pre-commit controls."""

from __future__ import annotations

import io
import json
import os
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.pre_commit_hook import main as detect_secrets_hook_main
from detect_secrets.util import git as detect_secrets_git

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRE_COMMIT_CONFIG = REPOSITORY_ROOT / ".pre-commit-config.yaml"
SECRETS_BASELINE = REPOSITORY_ROOT / ".secrets.baseline"
SYNTHETIC_MARKER_PARTS = ("AKIA", "W108SEC003TESTXY")
EXPECTED_PLUGIN_NAMES = (
    "ArtifactoryDetector",
    "AWSKeyDetector",
    "AzureStorageKeyDetector",
    "Base64HighEntropyString",
    "BasicAuthDetector",
    "CloudantDetector",
    "DiscordBotTokenDetector",
    "GitHubTokenDetector",
    "GitLabTokenDetector",
    "HexHighEntropyString",
    "IbmCloudIamDetector",
    "IbmCosHmacDetector",
    "IPPublicDetector",
    "JwtTokenDetector",
    "KeywordDetector",
    "MailchimpDetector",
    "NpmDetector",
    "OpenAIDetector",
    "PrivateKeyDetector",
    "PypiTokenDetector",
    "SendGridDetector",
    "SlackDetector",
    "SoftlayerDetector",
    "SquareOAuthDetector",
    "StripeDetector",
    "TelegramBotTokenDetector",
    "TwilioKeyDetector",
)
EXPECTED_FILTER_PATHS = (
    "detect_secrets.filters.allowlist.is_line_allowlisted",
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
    "detect_secrets.filters.heuristic.is_indirect_reference",
    "detect_secrets.filters.heuristic.is_likely_id_string",
    "detect_secrets.filters.heuristic.is_lock_file",
    "detect_secrets.filters.heuristic.is_not_alphanumeric_string",
    "detect_secrets.filters.heuristic.is_potential_uuid",
    "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign",
    "detect_secrets.filters.heuristic.is_sequential_string",
    "detect_secrets.filters.heuristic.is_swagger_file",
    "detect_secrets.filters.heuristic.is_templated_secret",
    "detect_secrets.filters.regex.should_exclude_file",
)
EXPECTED_REVIEWED_FINDING_COUNTS = {
    "configs/ci/w5-002.json": {"Hex High Entropy String": 12},
    "configs/eval/baselines/w3-002-v1.json": {"Hex High Entropy String": 6},
    "configs/rag/versions/w3-002-v1.json": {"Hex High Entropy String": 14},
    "configs/rag/versions/w3-004-synthetic-regression-v1.json": {"Hex High Entropy String": 14},
    "configs/releases/versions/w4-known-good-v1.json": {"Hex High Entropy String": 101},
    "configs/releases/versions/w4-synthetic-regression-v1.json": {"Hex High Entropy String": 101},
    "docker-compose.w2-004.yml": {"Base64 High Entropy String": 1},
    "docs/test-evidence/W2-09-retrieval.json": {"Hex High Entropy String": 2},
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py": {"Hex High Entropy String": 1},
    "src/enterprise_ai_platform/evaluation/fixtures.py": {"Hex High Entropy String": 3},
    "src/enterprise_ai_platform/rag_rollback/identity.py": {"Hex High Entropy String": 14},
    "src/enterprise_ai_platform/release_rollback/identity.py": {"Hex High Entropy String": 2},
    "src/enterprise_ai_platform/retrieval/models.py": {"Hex High Entropy String": 1},
    "tests/contract/test_embedder.py": {"Hex High Entropy String": 1},
    "tests/contract/test_w5_002_workflow_contract.py": {"Hex High Entropy String": 9},
    "tests/feature/test_local_retrieval.py": {"Hex High Entropy String": 1},
    "tests/integration/test_sentence_transformer_embedder.py": {"Hex High Entropy String": 1},
    "tests/integration/test_w5_002_ci_composition.py": {"Base64 High Entropy String": 1},
    "tests/teardown/test_w2_004_retrieval_cleanliness.py": {"Hex High Entropy String": 1},
    "tests/teardown/test_w3_002_evaluation_cleanliness.py": {"Hex High Entropy String": 1},
    "tests/teardown/test_w3_003_guardrails_cleanliness.py": {"Hex High Entropy String": 3},
    "tests/teardown/test_w3_004_rag_rollback_cleanliness.py": {"Hex High Entropy String": 6},
    "tests/teardown/test_w4_011_release_rollback_cleanliness.py": {"Hex High Entropy String": 2},
    "tests/unit/test_bedrock_owner_verify.py": {"Hex High Entropy String": 1},
    "tests/unit/test_evaluation_runner.py": {"Hex High Entropy String": 1},
    "tests/unit/test_prompt_template.py": {"Hex High Entropy String": 1},
    "tests/unit/test_retrieval_service.py": {"Hex High Entropy String": 1},
    "tools/bedrock_owner_verify.py": {"Hex High Entropy String": 1},
    "tools/platformctl/aws_inventory.py": {"Secret Keyword": 1},
    "tools/w5_002_ci.py": {"Hex High Entropy String": 16},
}
EXPECTED_REVIEWED_LINE_COUNTS = {
    "configs/ci/w5-002.json": {1: 12},
    "configs/eval/baselines/w3-002-v1.json": {1: 6},
    "configs/rag/versions/w3-002-v1.json": {
        6: 1,
        9: 1,
        13: 1,
        17: 1,
        18: 1,
        33: 1,
        34: 1,
        36: 1,
        41: 1,
        45: 1,
        47: 1,
        48: 1,
        52: 1,
        53: 1,
    },
    "configs/rag/versions/w3-004-synthetic-regression-v1.json": {
        6: 1,
        9: 1,
        13: 1,
        17: 1,
        18: 1,
        33: 1,
        34: 1,
        36: 1,
        41: 1,
        45: 1,
        47: 1,
        48: 1,
        52: 1,
        53: 1,
    },
    "configs/releases/versions/w4-known-good-v1.json": {1: 101},
    "configs/releases/versions/w4-synthetic-regression-v1.json": {1: 101},
    "docker-compose.w2-004.yml": {29: 1},
    "docs/test-evidence/W2-09-retrieval.json": {27: 1, 29: 1},
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py": {43: 1},
    "src/enterprise_ai_platform/evaluation/fixtures.py": {35: 1, 36: 1, 62: 1},
    "src/enterprise_ai_platform/rag_rollback/identity.py": {
        40: 1,
        41: 1,
        42: 1,
        43: 1,
        44: 1,
        45: 1,
        46: 1,
        47: 1,
        48: 1,
        49: 1,
        50: 1,
        51: 1,
        52: 1,
        53: 1,
    },
    "src/enterprise_ai_platform/release_rollback/identity.py": {27: 1, 29: 1},
    "src/enterprise_ai_platform/retrieval/models.py": {14: 1},
    "tests/contract/test_embedder.py": {17: 1},
    "tests/contract/test_w5_002_workflow_contract.py": {
        12: 1,
        13: 1,
        14: 1,
        15: 1,
        16: 1,
        17: 1,
        18: 1,
        111: 1,
        115: 1,
    },
    "tests/feature/test_local_retrieval.py": {46: 1},
    "tests/integration/test_sentence_transformer_embedder.py": {111: 1},
    "tests/integration/test_w5_002_ci_composition.py": {82: 1},
    "tests/teardown/test_w2_004_retrieval_cleanliness.py": {29: 1},
    "tests/teardown/test_w3_002_evaluation_cleanliness.py": {17: 1},
    "tests/teardown/test_w3_003_guardrails_cleanliness.py": {11: 1, 12: 1, 15: 1},
    "tests/teardown/test_w3_004_rag_rollback_cleanliness.py": {
        12: 1,
        15: 1,
        18: 1,
        20: 1,
        21: 1,
        23: 1,
    },
    "tests/teardown/test_w4_011_release_rollback_cleanliness.py": {59: 1, 62: 1},
    "tests/unit/test_bedrock_owner_verify.py": {367: 1},
    "tests/unit/test_evaluation_runner.py": {214: 1},
    "tests/unit/test_prompt_template.py": {35: 1},
    "tests/unit/test_retrieval_service.py": {142: 1},
    "tools/bedrock_owner_verify.py": {71: 1},
    "tools/platformctl/aws_inventory.py": {23: 1},
    "tools/w5_002_ci.py": {
        37: 1,
        41: 1,
        460: 1,
        461: 1,
        462: 1,
        463: 1,
        464: 1,
        465: 1,
        482: 1,
        505: 1,
        511: 1,
        531: 1,
        534: 1,
        537: 1,
        542: 1,
        952: 1,
    },
}
EXPECTED_BASELINE_FINDING_KEYS = {
    "type",
    "filename",
    "hashed_secret",
    "is_verified",
    "line_number",
}
SYNTHETIC_SOURCE_VALUES = (
    (
        "tests/fakes/telemetry.py",
        "_",
        ("PROMPT", "SECRET", "W4", "003"),
    ),
    (
        "tests/fakes/telemetry.py",
        "_",
        ("EVIDENCE", "TOKEN", "W4", "003"),
    ),
    (
        "tests/fakes/telemetry.py",
        "_",
        ("CREDENTIAL", "W4", "003"),
    ),
    (
        "tests/security/test_api_authorization.py",
        "_",
        ("SECRET", "W4", "001", "MUST", "NOT", "ESCAPE"),
    ),
    (
        "tests/security/test_configuration_security.py",
        "-",
        ("synthetic", "test", "value"),
    ),
    (
        "tests/security/test_embedder_security.py",
        "-",
        ("tenant", "secret", "never", "log"),
    ),
    (
        "tests/security/test_w3_001_cited_rag_security.py",
        "-",
        ("raw", "generated", "secret", "answer"),
    ),
    (
        "tests/security/test_w3_003_guardrails_security.py",
        "_",
        ("SECRET", "W3", "003", "DO", "NOT", "LOG"),
    ),
    (
        "tests/unit/test_api.py",
        "_",
        ("PROMPT", "AND", "EVIDENCE", "MUST", "NOT", "ESCAPE"),
    ),
)


def load_pre_commit_config() -> dict[str, Any]:
    data = yaml.safe_load(PRE_COMMIT_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def load_secrets_baseline() -> dict[str, Any]:
    data = json.loads(SECRETS_BASELINE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def snapshot_files(path: Path | None) -> tuple[str, ...]:
    if path is None or not path.exists():
        return ()
    return tuple(
        sorted(
            candidate.relative_to(path).as_posix()
            for candidate in path.rglob("*")
            if candidate.is_file()
        )
    )


def test_hook_inventory_order_provenance_and_commands_are_exact() -> None:
    config = load_pre_commit_config()
    assert set(config) == {"repos"}
    assert len(config["repos"]) == 1

    repository = config["repos"][0]
    assert set(repository) == {"repo", "hooks"}
    assert repository["repo"] == "local"

    hooks = repository["hooks"]
    assert [hook["id"] for hook in hooks] == [
        "ruff-lint-check",
        "ruff-format-check",
        "detect-secrets-check",
    ]
    assert all(hook["language"] == "system" for hook in hooks)
    assert all("additional_dependencies" not in hook for hook in hooks)

    lint_hook, format_hook, secrets_hook = hooks
    python_scope = r"^(src|tools|tests)/.*\.py$"
    assert lint_hook["entry"] == "python -m ruff check --no-cache"
    assert lint_hook["files"] == python_scope
    assert lint_hook["types"] == ["python"]
    assert "--fix" not in lint_hook["entry"]

    assert format_hook["entry"] == "python -m ruff format --check --no-cache"
    assert format_hook["files"] == python_scope
    assert format_hook["types"] == ["python"]

    assert secrets_hook["entry"] == ("detect-secrets-hook --baseline .secrets.baseline")
    assert secrets_hook["types"] == ["text"]
    assert secrets_hook["exclude"] == r"^\.secrets\.baseline$"


def test_secret_baseline_has_exact_default_and_reviewed_inventory() -> None:
    baseline = load_secrets_baseline()
    assert set(baseline) == {
        "version",
        "plugins_used",
        "filters_used",
        "results",
        "generated_at",
    }
    assert baseline["version"] == "1.5.0"
    assert tuple(plugin["name"] for plugin in baseline["plugins_used"]) == (EXPECTED_PLUGIN_NAMES)
    assert [plugin for plugin in baseline["plugins_used"] if set(plugin) != {"name"}] == [
        {"name": "Base64HighEntropyString", "limit": 4.5},
        {"name": "HexHighEntropyString", "limit": 3.0},
        {"name": "KeywordDetector", "keyword_exclude": ""},
    ]
    assert tuple(filter_["path"] for filter_ in baseline["filters_used"]) == (EXPECTED_FILTER_PATHS)
    results = baseline["results"]
    assert isinstance(results, dict)
    assert len(results) == 30
    assert sum(len(findings) for findings in results.values()) == 320
    actual_counts: dict[str, dict[str, int]] = {}
    actual_line_counts: dict[str, dict[int, int]] = {}
    for path, findings in results.items():
        assert isinstance(path, str)
        normalized_path = path.replace("\\", "/")
        assert isinstance(findings, list)
        finding_counts: Counter[str] = Counter()
        line_counts: Counter[int] = Counter()
        for finding in findings:
            assert isinstance(finding, dict)
            assert set(finding) == EXPECTED_BASELINE_FINDING_KEYS
            assert finding["filename"] == path
            assert isinstance(finding["line_number"], int) and finding["line_number"] > 0
            assert isinstance(finding["is_verified"], bool)
            line_counts[finding["line_number"]] += 1
            hashed_secret = finding["hashed_secret"]
            assert isinstance(hashed_secret, str) and len(hashed_secret) == 40
            assert all(character in "0123456789abcdef" for character in hashed_secret)
            finding_counts[finding["type"]] += 1
        actual_counts[normalized_path] = dict(finding_counts)
        actual_line_counts[normalized_path] = dict(line_counts)
    assert actual_counts == EXPECTED_REVIEWED_FINDING_COUNTS
    assert actual_line_counts == EXPECTED_REVIEWED_LINE_COUNTS
    assert baseline["filters_used"][1] == {
        "path": ("detect_secrets.filters.common.is_ignored_due_to_verification_policies"),
        "min_level": 2,
    }
    assert baseline["filters_used"][11] == {
        "path": "detect_secrets.filters.regex.should_exclude_file",
        "pattern": [r"^\.secrets\.baseline$"],
    }
    assert all(
        set(filter_) == {"path"}
        for index, filter_ in enumerate(baseline["filters_used"])
        if index not in {1, 11}
    )


def test_runtime_synthetic_aws_key_is_detected_without_disclosure_or_residue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    synthetic_path = tmp_path / "w1-08-synthetic-secret.txt"
    synthetic_value = "".join(SYNTHETIC_MARKER_PARTS)
    synthetic_line = f"credential={synthetic_value}\n"
    baseline_before = SECRETS_BASELINE.read_bytes()
    baseline_results_before = load_secrets_baseline()["results"]
    cache_value = os.environ.get("PRE_COMMIT_HOME")
    cache_path = Path(cache_value).resolve() if cache_value else None
    cache_before = snapshot_files(cache_path)

    synthetic_path.write_text(synthetic_line, encoding="utf-8")
    output = io.StringIO()
    error_output = io.StringIO()
    git_queries = 0

    def unchanged_baseline_files() -> tuple[()]:
        nonlocal git_queries
        git_queries += 1
        return ()

    monkeypatch.setattr(
        detect_secrets_git,
        "get_changed_but_unstaged_files",
        unchanged_baseline_files,
    )

    try:
        findings = list(
            AWSKeyDetector().analyze_line(
                filename=str(synthetic_path),
                line=synthetic_line,
            )
        )
        assert findings
        with redirect_stdout(output), redirect_stderr(error_output):
            result = detect_secrets_hook_main(
                ["--baseline", str(SECRETS_BASELINE), str(synthetic_path)]
            )
        captured = output.getvalue() + error_output.getvalue()
        assert result != 0
        assert synthetic_value not in captured
        assert SECRETS_BASELINE.read_bytes() == baseline_before
        assert load_secrets_baseline()["results"] == baseline_results_before
        assert git_queries == 1
    finally:
        synthetic_path.unlink(missing_ok=True)

    assert not synthetic_path.exists()
    assert snapshot_files(cache_path) == cache_before


def test_complete_synthetic_value_is_not_committed_in_control_sources() -> None:
    synthetic_value = "".join(SYNTHETIC_MARKER_PARTS)
    source_paths = (
        Path(__file__),
        REPOSITORY_ROOT / "tests/security/test_evidence_redaction.py",
        PRE_COMMIT_CONFIG,
        SECRETS_BASELINE,
    )
    assert all(synthetic_value not in path.read_text(encoding="utf-8") for path in source_paths)


def test_reviewed_synthetic_fixtures_are_constructed_only_at_runtime() -> None:
    for path, separator, parts in SYNTHETIC_SOURCE_VALUES:
        synthetic_value = separator.join(parts)
        source = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
        assert synthetic_value not in source
