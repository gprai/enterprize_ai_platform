"""Security tests for placeholders, secrets, imports, and API output."""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = REPOSITORY_ROOT / ".env.example"
SOURCE_ROOT = REPOSITORY_ROOT / "src" / "enterprise_ai_platform"


def example_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, value = stripped.split("=", maxsplit=1)
        values[key] = value
    return values


def test_environment_example_contains_only_approved_values() -> None:
    values = example_values()

    assert values["ENTERPRISE_AI_LLM_PROVIDER"] == "fake"
    assert values["ENTERPRISE_AI_LLM_MODEL_ID"] == ""
    assert values["ENTERPRISE_AI_AWS_REGION"] == ""
    assert (
        values["ENTERPRISE_AI_EMBEDDING_MODEL_ID"]
        == "sentence-transformers/all-MiniLM-L6-v2"
    )
    assert values["ENTERPRISE_AI_QDRANT_URL"] == "http://127.0.0.1:6333"
    assert values["ENTERPRISE_AI_OPENSEARCH_URL"] == "TODO_USER"
    assert values["ENTERPRISE_AI_QDRANT_API_KEY"] == ""
    assert values["ENTERPRISE_AI_API_ROUTES_ENABLED"] == "false"
    assert values["ENTERPRISE_AI_API_MAX_REQUEST_BODY_BYTES"] == "131072"
    assert values["ENTERPRISE_AI_API_READINESS_TIMEOUT_SECONDS"] == "1.0"
    assert values["ENTERPRISE_AI_API_MAX_INFLIGHT_QUERIES"] == "4"
    assert values["ENTERPRISE_AI_API_QUERY_QUEUE_CAPACITY"] == "0"
    assert "AWS_ACCESS_KEY_ID" not in values
    assert "AWS_SECRET_ACCESS_KEY" not in values
    assert "AWS_SESSION_TOKEN" not in values


def test_secret_is_masked_and_absent_from_health_output(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["qdrant_api_key"] = "synthetic-test-value"
    settings = Settings(_env_file=None, **values)

    assert "synthetic-test-value" not in repr(settings)

    response = TestClient(create_app(settings)).get("/health")
    assert "synthetic-test-value" not in response.text
    assert "qdrant" not in response.text.casefold()
    assert "opensearch" not in response.text.casefold()


def test_foundation_source_imports_no_rag_or_external_client_runtime() -> None:
    forbidden_imports = {
        "boto3",
        "langchain",
        "langgraph",
        "opensearchpy",
        "presidio_analyzer",
        "presidio_anonymizer",
        "qdrant_client",
        "sentence_transformers",
    }
    findings: list[str] = []

    for path in SOURCE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    if imported.name.split(".")[0] in forbidden_imports:
                        findings.append(f"{path.name}: {imported.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in forbidden_imports:
                    findings.append(f"{path.name}: {node.module}")

    assert findings == []


def test_api_defaults_add_no_proxy_identity_or_network_configuration() -> None:
    values = example_values()
    forbidden = (
        "CORS",
        "JWT",
        "JWKS",
        "PROXY",
        "TRUSTED_HOST",
        "API_KEY",
        "PUBLIC_HOST",
    )

    assert not any(
        token in key
        for key in values
        for token in forbidden
        if key != "ENTERPRISE_AI_QDRANT_API_KEY"
    )
