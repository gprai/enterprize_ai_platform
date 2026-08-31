"""Static lifecycle tests that do not invoke Docker."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPOSITORY_ROOT / "docker-compose.yml"
QDRANT_TEST_PATH = REPOSITORY_ROOT / "tests/integration/test_qdrant.py"
RUNNER_DOCKERFILE_PATH = REPOSITORY_ROOT / "docker/qdrant-test-runner.Dockerfile"
RUNNER_DOCKERIGNORE_PATH = REPOSITORY_ROOT / "docker/qdrant-test-runner.Dockerfile.dockerignore"
RUNNER_REQUIREMENTS_PATH = REPOSITORY_ROOT / "docker/qdrant-test-runner.requirements.txt"
INDEX_DIGEST = "sha256:a0e04fe623cb064502cd869cefc1dc7ce359d8edd481063b5bd351c0a0a2c91e"
PYTHON_INDEX_DIGEST = "sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d"
PYTHON_AMD64_MANIFEST_DIGEST = (
    "sha256:781449467ffb6f04218f09b1ecdcdc7d22b289ee5da9ec498b024e24ad7a6db7"
)
PYTHON_ATTESTATION_MANIFEST_DIGEST = (
    "sha256:b8aaccd8c14d29d4af8961f1d1151d7db432ff131d0d5c61138f681578e8afb2"
)


def compose_text() -> str:
    return COMPOSE_PATH.read_text(encoding="utf-8")


def service_text(service_name: str) -> str:
    marker = f"  {service_name}:"
    lines = compose_text().splitlines()
    start = lines.index(marker)
    body = [lines[start]]
    for line in lines[start + 1 :]:
        if line and not line.startswith("    "):
            break
        body.append(line)
    return "\n".join(body)


def test_qdrant_identity_platform_and_internal_only_are_exact() -> None:
    content = compose_text()
    qdrant = service_text("qdrant")
    assert "name: enterprise-ai-w2-004a" in content
    assert ("qdrant/qdrant:v1.19.0-unprivileged@" + INDEX_DIGEST) in content
    assert "platform: linux/amd64" in qdrant
    assert "ports:" not in qdrant
    assert "host_ip:" not in qdrant
    assert "published:" not in qdrant
    assert "- qdrant_internal" in qdrant


def test_qdrant_has_bounded_unprivileged_health_and_resources() -> None:
    content = service_text("qdrant")
    required = (
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "pids_limit: 256",
        'cpus: "1.0"',
        "mem_limit: 1g",
        "healthcheck:",
        "timeout: 2s",
        "retries: 30",
        "stop_grace_period: 20s",
    )
    assert all(value in content for value in required)
    assert "privileged: true" not in content
    assert "network_mode: host" not in content
    assert "api_key" not in content.casefold()


def test_project_volume_and_internal_network_are_exact() -> None:
    content = compose_text()
    network_definition = content.partition("\nnetworks:\n")[2]
    assert "enterprise-ai-w2-004a_qdrant_data" in content
    assert "\nnetworks:\n  qdrant_internal:\n    internal: true" in content
    assert "    name:" not in network_definition


def test_runner_is_profile_controlled_internal_and_ephemeral() -> None:
    runner = service_text("qdrant_test_runner")
    required = (
        'profiles:\n      - "qdrant-test"',
        "dockerfile: docker/qdrant-test-runner.Dockerfile",
        "platform: linux/amd64",
        "condition: service_healthy",
        'ENTERPRISE_AI_RUN_QDRANT_INTEGRATION: "1"',
        'ENTERPRISE_AI_QDRANT_INTEGRATION_URL: "http://qdrant:6333"',
        "- qdrant_internal",
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "pids_limit: 128",
        'cpus: "1.0"',
        "mem_limit: 512m",
        "tmpfs:",
    )
    assert all(value in runner for value in required)
    forbidden = (
        "ports:",
        "volumes:",
        "network_mode:",
        "docker.sock",
        "privileged: true",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    )
    assert all(value not in runner for value in forbidden)


def test_runner_image_identity_and_non_root_execution_are_exact() -> None:
    content = RUNNER_DOCKERFILE_PATH.read_text(encoding="utf-8")
    expected_from = "FROM --platform=linux/amd64 python:3.13.7-slim-bookworm@" + PYTHON_INDEX_DIGEST
    assert expected_from in content
    assert PYTHON_AMD64_MANIFEST_DIGEST in content
    assert PYTHON_ATTESTATION_MANIFEST_DIGEST not in content
    assert "# syntax=" not in content
    assert "docker/dockerfile" not in content
    assert "VIRTUAL_ENV=/opt/qdrant-test-runner-venv" in content
    assert 'PATH="${VIRTUAL_ENV}/bin:${PATH}"' in content
    assert 'python -m venv "${VIRTUAL_ENV}"' in content
    assert "--uid 10001" in content
    assert "--gid 10001" in content
    assert "USER 10001:10001" in content
    assert "--no-cache-dir" in content
    assert "ENTRYPOINT" in content


def test_runner_uses_only_approved_dependency_families() -> None:
    requirements = tuple(
        line for line in RUNNER_REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines() if line
    )
    assert requirements == (
        "pydantic>=2.10,<3",
        "pytest>=8,<10",
        "qdrant-client>=1.18,<2",
    )


def test_runner_build_context_allowlist_is_exact() -> None:
    patterns = tuple(RUNNER_DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines())
    assert patterns == (
        "**",
        "!docker/",
        "!docker/qdrant-test-runner.Dockerfile",
        "!docker/qdrant-test-runner.Dockerfile.dockerignore",
        "!docker/qdrant-test-runner.requirements.txt",
        "!src/",
        "!src/enterprise_ai_platform/",
        "!src/enterprise_ai_platform/__init__.py",
        "!src/enterprise_ai_platform/retrieval/",
        "!src/enterprise_ai_platform/retrieval/__init__.py",
        "!src/enterprise_ai_platform/retrieval/authorization.py",
        "!src/enterprise_ai_platform/retrieval/errors.py",
        "!src/enterprise_ai_platform/retrieval/models.py",
        "!src/enterprise_ai_platform/retrieval/vector_store.py",
        "!src/enterprise_ai_platform/retrieval/adapters/",
        "!src/enterprise_ai_platform/retrieval/adapters/__init__.py",
        "!src/enterprise_ai_platform/retrieval/adapters/fake.py",
        "!src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
        "!src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
        "!tests/",
        "!tests/integration/",
        "!tests/integration/test_qdrant.py",
    )


def test_integration_contract_deletes_its_collection_in_finally() -> None:
    content = QDRANT_TEST_PATH.read_text(encoding="utf-8")
    assert 'INTERNAL_QDRANT_URL = "http://qdrant:6333"' in content
    assert "finally:" in content
    assert "await client.delete_collection(specification.name)" in content
    assert "assert not await client.collection_exists(specification.name)" in content
    assert "await client.close()" in content
