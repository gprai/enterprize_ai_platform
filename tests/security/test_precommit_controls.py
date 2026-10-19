"""Security contracts for the W1-08 local pre-commit controls."""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml
from detect_secrets.plugins.aws import AWSKeyDetector
from tools import secret_scan

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
    "configs/lifecycle/w5-004.json": {"Hex High Entropy String": 5},
    "tests/security/test_w5_004_lifecycle_security.py": {"Hex High Entropy String": 2},
    "tests/unit/test_platformctl_cost.py": {"Hex High Entropy String": 1},
    "tests/unit/test_platformctl_plan_identity.py": {"Hex High Entropy String": 1},
    "tools/platformctl/cost.py": {"Hex High Entropy String": 3},
    "tools/platformctl/lifecycle_io.py": {"Hex High Entropy String": 5},
    "tools/platformctl/policy_runner.py": {"Hex High Entropy String": 23},
    "tools/w6_003_readiness.py": {"Hex High Entropy String": 1},
    "configs/ci/w5-002.json": {"Hex High Entropy String": 12},
    "configs/eval/baselines/w3-002-v1.json": {"Hex High Entropy String": 6},
    "configs/readiness/local-integrated-readiness.yaml": {"Hex High Entropy String": 1},
    "configs/rag/versions/w3-002-v1.json": {"Hex High Entropy String": 14},
    "configs/rag/versions/w3-004-synthetic-regression-v1.json": {"Hex High Entropy String": 14},
    "configs/rag/versions/known-good-v2.json": {"Hex High Entropy String": 14},
    "configs/rag/versions/synthetic-regression-v2.json": {"Hex High Entropy String": 14},
    "configs/releases/versions/w4-known-good-v1.json": {"Hex High Entropy String": 101},
    "configs/releases/versions/w4-synthetic-regression-v1.json": {"Hex High Entropy String": 101},
    "docker-compose.w2-004.yml": {"Base64 High Entropy String": 1},
    "docs/resource-cleanliness/W5-report.json": {"Hex High Entropy String": 1},
    "docs/resource-cleanliness/W6-final.json": {"Hex High Entropy String": 3},
    "docs/test-evidence/W10/W10-003.md": {"Hex High Entropy String": 1},
    "docs/test-evidence/W2/W2-09-retrieval.json": {"Hex High Entropy String": 2},
    "docs/test-evidence/W6/W6-06-observability.json": {"Hex High Entropy String": 4},
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py": {"Hex High Entropy String": 1},
    "src/enterprise_ai_platform/evaluation/fixtures.py": {"Hex High Entropy String": 3},
    "src/enterprise_ai_platform/evaluation/rag_safety.py": {"Hex High Entropy String": 1},
    "src/enterprise_ai_platform/evaluation/rag_safety_runner.py": {"Hex High Entropy String": 2},
    "src/enterprise_ai_platform/rag_rollback/identity.py": {"Hex High Entropy String": 13},
    "src/enterprise_ai_platform/release_rollback/identity.py": {"Hex High Entropy String": 2},
    "src/enterprise_ai_platform/retrieval/models.py": {"Hex High Entropy String": 1},
    "tests/contract/test_embedder.py": {"Hex High Entropy String": 1},
    "tests/contract/test_w5_002_workflow_contract.py": {"Hex High Entropy String": 9},
    "tests/fakes/w10_003_rag_evaluation.py": {"Hex High Entropy String": 3},
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
    "tools/w6_004_stage6_transcript.py": {"Secret Keyword": 1},
}
EXPECTED_REVIEWED_LINE_COUNTS = {
    "configs/ci/w5-002.json": {1: 12},
    "configs/eval/baselines/w3-002-v1.json": {1: 6},
    "configs/lifecycle/w5-004.json": {6: 1, 7: 1, 86: 1, 90: 1, 91: 1},
    "configs/readiness/local-integrated-readiness.yaml": {4: 1},
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
    "configs/rag/versions/known-good-v2.json": {
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
    "configs/rag/versions/synthetic-regression-v2.json": {
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
    "docs/resource-cleanliness/W5-report.json": {61: 1},
    "docs/resource-cleanliness/W6-final.json": {43: 1, 70: 1, 72: 1},
    "docs/test-evidence/W10/W10-003.md": {279: 1},
    "docs/test-evidence/W2/W2-09-retrieval.json": {27: 1, 29: 1},
    "docs/test-evidence/W6/W6-06-observability.json": {6: 1, 11: 1, 54: 1, 55: 1},
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py": {43: 1},
    "src/enterprise_ai_platform/evaluation/fixtures.py": {35: 1, 36: 1, 62: 1},
    "src/enterprise_ai_platform/evaluation/rag_safety.py": {241: 1},
    "src/enterprise_ai_platform/evaluation/rag_safety_runner.py": {175: 1, 177: 1},
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
        52: 1,
        53: 1,
        54: 1,
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
    "tests/fakes/w10_003_rag_evaluation.py": {43: 1, 45: 1, 52: 1},
    "tests/feature/test_local_retrieval.py": {46: 1},
    "tests/integration/test_sentence_transformer_embedder.py": {111: 1},
    "tests/integration/test_w5_002_ci_composition.py": {84: 1},
    "tests/security/test_w5_004_lifecycle_security.py": {391: 1, 392: 1},
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
    "tests/unit/test_platformctl_cost.py": {644: 1},
    "tests/unit/test_platformctl_plan_identity.py": {77: 1},
    "tests/unit/test_prompt_template.py": {35: 1},
    "tests/unit/test_retrieval_service.py": {142: 1},
    "tools/bedrock_owner_verify.py": {71: 1},
    "tools/platformctl/aws_inventory.py": {61: 1},
    "tools/platformctl/cost.py": {46: 1, 48: 1, 51: 1},
    "tools/platformctl/lifecycle_io.py": {34: 1, 1016: 1, 1042: 1, 1044: 1, 1075: 1},
    "tools/platformctl/policy_runner.py": {
        102: 1,
        106: 1,
        110: 1,
        116: 1,
        147: 1,
        153: 1,
        295: 1,
        298: 1,
        301: 1,
        304: 1,
        307: 1,
        310: 1,
        316: 1,
        332: 1,
        341: 1,
        344: 1,
        347: 1,
        350: 1,
        354: 1,
        355: 1,
        359: 1,
        365: 1,
        402: 1,
    },
    "tools/w5_002_ci.py": {
        39: 1,
        43: 1,
        545: 1,
        546: 1,
        547: 1,
        548: 1,
        549: 1,
        550: 1,
        567: 1,
        590: 1,
        596: 1,
        616: 1,
        619: 1,
        622: 1,
        627: 1,
        1038: 1,
    },
    "tools/w6_003_readiness.py": {23: 1},
    "tools/w6_004_stage6_transcript.py": {348: 1},
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

    assert secrets_hook["entry"] == "python -B -m tools.secret_scan check --"
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
    assert len(results) == 49
    assert sum(len(findings) for findings in results.values()) == 405
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

    def unchanged_baseline_files(*_args: object) -> bytes:
        nonlocal git_queries
        git_queries += 1
        return b"fixture-index"

    monkeypatch.setattr(
        secret_scan,
        "_assert_staged",
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
            result = secret_scan.main(["check", str(synthetic_path)])
        captured = output.getvalue() + error_output.getvalue()
        assert result != 0
        assert synthetic_value not in captured
        assert SECRETS_BASELINE.read_bytes() == baseline_before
        assert load_secrets_baseline()["results"] == baseline_results_before
        assert git_queries == 2
    finally:
        synthetic_path.unlink(missing_ok=True)

    assert not synthetic_path.exists()
    assert snapshot_files(cache_path) == cache_before


def test_complete_synthetic_value_is_not_committed_in_control_sources() -> None:
    synthetic_value = "".join(SYNTHETIC_MARKER_PARTS)
    source_paths = (
        REPOSITORY_ROOT / "tools/secret_scan.py",
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


@pytest.fixture
def scanner_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A disposable index, never the user's index, with the real installed scanner."""
    root = tmp_path / "scanner-repository"
    root.mkdir()
    executable = shutil.which("git")
    assert executable

    def git(*arguments: str) -> bytes:
        result = subprocess.run(  # noqa: S603 -- disposable fixture and explicit Git commands
            [executable, "-C", str(root), *arguments],
            capture_output=True,
            check=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
        return result.stdout

    git("init", "-q")
    baseline = {
        "version": "1.5.0",
        **secret_scan.scanner_configuration(),
        "results": {},
        "generated_at": "2026-09-13T00:00:00Z",
    }
    path = root / ".secrets.baseline"
    path.write_text(json.dumps(baseline), encoding="utf-8")
    git("-c", "core.autocrlf=false", "add", "--", ".secrets.baseline")
    monkeypatch.setattr(secret_scan, "REPOSITORY", root)
    return root, baseline, git


def test_check_only_scans_nested_and_external_baseline_names(
    scanner_repository, tmp_path: Path, capsys
):
    root, _, git = scanner_repository
    original = (root / ".secrets.baseline").read_bytes()
    index = git("ls-files", "--stage", "-z")
    assert secret_scan.main(["check", ".secrets.baseline"]) == 0
    synthetic = "".join(SYNTHETIC_MARKER_PARTS)
    paths = [
        root / "src/.secrets.baseline",
        root / "tests/.secrets.baseline",
        root / "evidence/.secrets.baseline",
        tmp_path / ".secrets.baseline",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"credential={synthetic}\n", encoding="utf-8")
        assert secret_scan.main(["check", str(path)]) == 1
        captured = capsys.readouterr()
        assert synthetic not in captured.out + captured.err
        assert '"type": "AWS Access Key"' in captured.out
    assert (root / ".secrets.baseline").read_bytes() == original
    assert git("ls-files", "--stage", "-z") == index


def test_partial_scope_preserves_unscanned_findings_and_complete_scope_detects_missing(
    scanner_repository,
):
    root, baseline, git = scanner_repository
    baseline["results"] = {
        "unscanned.txt": [
            {
                "type": "AWS Access Key",
                "filename": "unscanned.txt",
                "hashed_secret": "a" * 40,
                "is_verified": False,
                "line_number": 1,
            }
        ]
    }
    (root / ".secrets.baseline").write_text(json.dumps(baseline), encoding="utf-8")
    git("add", "--", ".secrets.baseline")
    (root / "clean.txt").write_text("ordinary text\n", encoding="utf-8")
    assert secret_scan.check(root, ["clean.txt"]).passed
    complete = secret_scan.check(root, [], complete=True)
    assert complete.missing == 1 and not complete.passed


def test_check_rejects_unstaged_baseline_without_changing_index(scanner_repository):
    root, baseline, git = scanner_repository
    before = git("ls-files", "--stage", "-z")
    baseline["generated_at"] = "2026-09-13T01:00:00Z"
    (root / ".secrets.baseline").write_text(json.dumps(baseline), encoding="utf-8")
    with pytest.raises(secret_scan.ScanError, match="UNSTAGED"):
        secret_scan.check(root, [".secrets.baseline"])
    assert git("ls-files", "--stage", "-z") == before


def test_check_preserves_working_crlf_and_distinct_normalized_index(scanner_repository):
    root, baseline, git = scanner_repository
    raw = (json.dumps(baseline, indent=2) + "\n").replace("\n", "\r\n").encode()
    path = root / ".secrets.baseline"
    (root / ".gitattributes").write_text(".secrets.baseline text eol=lf\n", encoding="utf-8")
    path.write_bytes(raw)
    git("add", "--", ".secrets.baseline")
    assert git("show", ":.secrets.baseline") == raw.replace(b"\r\n", b"\n")
    assert secret_scan.check(root, [".secrets.baseline"]).passed
    assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "name",
    [
        "../.secrets.baseline",
        "src/../.secrets.baseline",
        "./.secrets.baseline.",
        "./.secrets.baseline ",
        "src/data:stream",
        "bad\nname",
    ],
)
def test_scanner_rejects_unsafe_aliases(scanner_repository, name: str):
    root, _, _ = scanner_repository
    with pytest.raises((secret_scan.ScanError, OSError)):
        secret_scan.check(root, [name])


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "parent_link"])
def test_scanner_rejects_physical_baseline_aliases(scanner_repository, kind: str):
    root, _, _ = scanner_repository
    nested = root / "nested"
    nested.mkdir()
    alias = nested / ".secrets.baseline"
    if kind == "symlink":
        alias.symlink_to(root / ".secrets.baseline")
    elif kind == "hardlink":
        os.link(root / ".secrets.baseline", alias)
    else:
        alias = root / "linked/.secrets.baseline"
        (root / "linked").symlink_to(root, target_is_directory=True)
    from tools.platformctl.contracts import ContractError

    with pytest.raises((secret_scan.ScanError, ContractError)):
        secret_scan.check(root, [str(alias)])


def test_real_scanner_offline_verification_keeps_potential_finding(
    scanner_repository, monkeypatch, capsys
):
    root, _, _ = scanner_repository
    import requests
    from detect_secrets.plugins.aws import AWSKeyDetector

    synthetic = "".join(SYNTHETIC_MARKER_PARTS)
    (root / "paired.txt").write_text(
        "credential=" + synthetic + "\naws_secret_access_key='" + ("x" * 40) + "'\n",
        encoding="utf-8",
    )
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Real transport prohibited")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "send", forbidden)
    monkeypatch.setattr(AWSKeyDetector, "verify", forbidden)
    assert secret_scan.main(["check", "paired.txt"]) == 1
    assert calls == []
    captured = capsys.readouterr()
    assert synthetic not in captured.out + captured.err
    assert "AWS Access Key" in captured.out


def test_duplicate_identity_preserves_upstream_first_occurrence(scanner_repository):
    from detect_secrets.core.potential_secret import PotentialSecret

    root, baseline, git = scanner_repository
    synthetic = "".join(SYNTHETIC_MARKER_PARTS)
    row = PotentialSecret("AWS Access Key", "repeated.txt", synthetic, line_number=1).json()
    baseline["results"] = {"repeated.txt": [row]}
    (root / ".secrets.baseline").write_text(json.dumps(baseline), encoding="utf-8")
    git("add", "--", ".secrets.baseline")
    (root / "repeated.txt").write_text(
        "credential=" + synthetic + "\ncredential=" + synthetic + "\n", encoding="utf-8"
    )
    result = secret_scan.check(root, ["repeated.txt"])
    assert result.passed
    assert result.candidate["results"]["repeated.txt"][0] == row


def test_metadata_relocation_fails_check_without_mutating_and_maintenance_is_separate(
    scanner_repository, tmp_path, monkeypatch
):
    root, baseline, git = scanner_repository
    from hashlib import sha256

    from detect_secrets.core.potential_secret import PotentialSecret

    synthetic = "".join(SYNTHETIC_MARKER_PARTS)
    row = PotentialSecret("AWS Access Key", "relocated.txt", synthetic, line_number=1).json()
    baseline["results"] = {"relocated.txt": [row]}
    reference = (json.dumps(baseline, indent=2) + "\n").encode()
    (root / ".secrets.baseline").write_bytes(reference)
    git("add", "--", ".secrets.baseline")
    (root / "relocated.txt").write_text("\ncredential=" + synthetic + "\n", encoding="utf-8")
    result = secret_scan.check(root, ["relocated.txt"])
    assert result.relocated == 1 and not result.passed
    index = git("ls-files", "--stage", "-z")
    external = tmp_path / "external"
    external.mkdir()
    monkeypatch.setattr(secret_scan, "MAINTENANCE_PARENT", external)
    output = external / "secret-scanning-maintenance-001"
    result = secret_scan.maintain(root, reference, sha256(reference).hexdigest(), output)
    assert result.relocated == 1
    assert (root / ".secrets.baseline").read_bytes() == reference
    assert git("ls-files", "--stage", "-z") == index
    assert {p.name for p in output.iterdir()} == {
        "approved-reference.lf.json",
        "starting-working.json",
        "candidate.json",
        "identities.json",
    }
    candidate = json.loads((output / "candidate.json").read_text())
    assert candidate["results"]["relocated.txt"][0] == {**row, "line_number": 2}
    from tools.platformctl.contracts import ContractError

    with pytest.raises(ContractError, match="COLLISION"):
        secret_scan.maintain(root, reference, sha256(reference).hexdigest(), output)


def test_check_fails_on_invalid_configuration_and_unreadable_text(scanner_repository):
    root, baseline, git = scanner_repository
    (root / "invalid.txt").write_bytes(b"\xff\xfe\x00")
    with pytest.raises((secret_scan.ScanError, UnicodeError)):
        secret_scan.check(root, ["invalid.txt"])
    baseline["filters_used"].append(
        {"path": "detect_secrets.filters.common.is_baseline_file", "filename": ".secrets.baseline"}
    )
    (root / ".secrets.baseline").write_text(json.dumps(baseline), encoding="utf-8")
    git("add", "--", ".secrets.baseline")
    with pytest.raises(secret_scan.ScanError, match="CONFIGURATION"):
        secret_scan.check(root, [".secrets.baseline"])


def test_ci_and_hook_share_check_only_adapter_and_strict_typing():
    workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text()
    assert "python -B -m tools.secret_scan check --all-files" in workflow
    assert "detect-secrets scan --baseline" not in workflow
    assert "detect-secrets-hook --baseline" not in PRE_COMMIT_CONFIG.read_text()
    assert '"tools/secret_scan.py"' in (REPOSITORY_ROOT / "pyproject.toml").read_text()


def test_scanner_warning_and_exception_fail_closed_without_disclosure(
    scanner_repository, monkeypatch, capsys
):
    root, _, git = scanner_repository
    from detect_secrets.core import scan
    from detect_secrets.core.log import log

    (root / "plain.txt").write_text("ordinary\n", encoding="utf-8")
    before = (root / ".secrets.baseline").read_bytes()
    index = git("ls-files", "--stage", "-z")
    synthetic = "".join(SYNTHETIC_MARKER_PARTS)

    def warning(_name):
        log.warning(synthetic)
        return iter(())

    monkeypatch.setattr(scan, "scan_file", warning)
    assert secret_scan.main(["check", "plain.txt"]) == 1
    assert synthetic not in capsys.readouterr().out

    def failure(_name):
        raise RuntimeError(synthetic)

    monkeypatch.setattr(scan, "scan_file", failure)
    assert secret_scan.main(["check", "plain.txt"]) == 1
    captured = capsys.readouterr()
    assert synthetic not in captured.out + captured.err
    assert (root / ".secrets.baseline").read_bytes() == before
    assert git("ls-files", "--stage", "-z") == index


def test_maintenance_rejects_inventory_or_decision_changes(
    scanner_repository, tmp_path, monkeypatch
):
    from hashlib import sha256

    root, baseline, _ = scanner_repository
    reference = json.dumps(baseline).encode()
    baseline["results"] = {
        "different.txt": [
            {
                "filename": "different.txt",
                "type": "AWS Access Key",
                "line_number": 1,
                "hashed_secret": "a" * 40,
                "is_verified": False,
            }
        ]
    }
    (root / ".secrets.baseline").write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setattr(secret_scan, "MAINTENANCE_PARENT", tmp_path)
    output = tmp_path / "secret-scanning-maintenance-002"
    with pytest.raises(secret_scan.ScanError, match="REFERENCE_FINDINGS"):
        secret_scan.maintain(root, reference, sha256(reference).hexdigest(), output)
    assert not output.exists()
