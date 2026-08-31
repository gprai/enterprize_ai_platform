"""Static W2-004 lifecycle contracts that never invoke Docker or the model."""

from __future__ import annotations

from pathlib import Path

import yaml
from tools.verify_w2_004_local import (
    READ_ONLY_COMMANDS,
    CheckResult,
    State,
    exit_code,
)

ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE_PATH = ROOT / "docker-compose.yml"
OVERRIDE_COMPOSE_PATH = ROOT / "docker-compose.w2-004.yml"
DOCKERFILE_PATH = ROOT / "docker/local-retrieval-runner.Dockerfile"
DOCKERIGNORE_PATH = ROOT / "docker/local-retrieval-runner.Dockerfile.dockerignore"
REQUIREMENTS_PATH = ROOT / "docker/local-retrieval-runner.requirements.txt"
PYTHON_INDEX_DIGEST = "sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d"
PYTHON_AMD64_MANIFEST_DIGEST = (
    "sha256:781449467ffb6f04218f09b1ecdcdc7d22b289ee5da9ec498b024e24ad7a6db7"
)
PYTHON_ATTESTATION_DIGEST = (
    "sha256:b8aaccd8c14d29d4af8961f1d1151d7db432ff131d0d5c61138f681578e8afb2"
)
QDRANT_INDEX_DIGEST = "sha256:a0e04fe623cb064502cd869cefc1dc7ce359d8edd481063b5bd351c0a0a2c91e"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
APPROVED_TMPFS = "/tmp:size=64m,mode=1777"  # noqa: S108 - exact secured tmpfs contract


def load_yaml(path: Path) -> dict[str, object]:
    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(content, dict)
    return content


def runner_service() -> dict[str, object]:
    services = load_yaml(OVERRIDE_COMPOSE_PATH)["services"]
    assert isinstance(services, dict)
    runner = services["local_retrieval_runner"]
    assert isinstance(runner, dict)
    return runner


def test_qdrant_and_runner_share_only_the_internal_logical_network() -> None:
    base = load_yaml(BASE_COMPOSE_PATH)
    override = load_yaml(OVERRIDE_COMPOSE_PATH)
    base_services = base["services"]
    networks = base["networks"]
    assert isinstance(base_services, dict)
    assert isinstance(networks, dict)
    qdrant = base_services["qdrant"]
    runner = override["services"]["local_retrieval_runner"]
    assert qdrant["networks"] == ["qdrant_internal"]
    assert runner["networks"] == ["qdrant_internal"]
    assert qdrant["image"].endswith(f"@{QDRANT_INDEX_DIGEST}")
    assert "ports" not in qdrant
    assert "ports" not in runner
    assert networks == {"qdrant_internal": {"internal": True}}
    assert "name" not in networks["qdrant_internal"]


def test_runner_has_no_host_access_credentials_or_persistent_storage() -> None:
    runner = runner_service()
    assert runner["profiles"] == ["local-retrieval"]
    assert runner["platform"] == "linux/amd64"
    assert runner["user"] == "10001:10001"
    assert runner["read_only"] is True
    assert runner["cap_drop"] == ["ALL"]
    assert runner["security_opt"] == ["no-new-privileges:true"]
    assert runner["pids_limit"] == 256
    assert runner["cpus"] == 2
    assert runner["mem_limit"] == "2g"
    assert runner["tmpfs"] == [APPROVED_TMPFS]
    assert runner["depends_on"] == {"qdrant": {"condition": "service_healthy"}}
    for forbidden in (
        "ports",
        "network_mode",
        "privileged",
        "devices",
        "secrets",
    ):
        assert forbidden not in runner
    serialized = OVERRIDE_COMPOSE_PATH.read_text(encoding="utf-8").casefold()
    assert "docker.sock" not in serialized
    assert "aws_access_key_id" not in serialized
    assert "aws_secret_access_key" not in serialized
    assert "token:" not in serialized


def test_runtime_inputs_are_the_exact_read_only_allowlist() -> None:
    volumes = runner_service()["volumes"]
    assert isinstance(volumes, list)
    assert len(volumes) == 8
    assert all(volume["type"] == "bind" for volume in volumes)
    assert all(volume["read_only"] is True for volume in volumes)
    targets = [volume["target"] for volume in volumes]
    assert targets == [
        "/opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/"
        f"snapshots/{MODEL_REVISION}",
        "/opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/blobs",
        "/workspace/configs/pii-policy.yaml",
        "/workspace/configs/eval/w2-starter.jsonl",
        "/workspace/data/sample/corpus-manifest.json",
        "/workspace/data/sample/approved/source-of-truth-v1.1.md",
        "/workspace/data/sample/approved/coaching-blueprint.md",
        "/workspace/data/sample/restricted-fixtures/restricted-test.txt",
    ]
    assert "W2_002_MODEL_BLOBS_HOST" in OVERRIDE_COMPOSE_PATH.read_text(encoding="utf-8")


def test_runner_identity_offline_controls_and_provenance_are_exact() -> None:
    environment = runner_service()["environment"]
    assert environment == {
        "RUN_W2_004_LOCAL_RETRIEVAL": "1",
        "W2_004_QDRANT_URL": "http://qdrant:6333",
        "W2_004_MODEL_SNAPSHOT": (
            "/opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/"
            f"snapshots/{MODEL_REVISION}"
        ),
        "HF_HOME": "/opt/model-cache",
        "HF_HUB_CACHE": "/opt/model-cache",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "CUDA_VISIBLE_DEVICES": "-1",
    }
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert (
        "FROM --platform=linux/amd64 "
        "docker.io/library/python:3.13.7-slim-bookworm@"
        f"{PYTHON_INDEX_DIGEST}"
    ) in dockerfile
    assert PYTHON_AMD64_MANIFEST_DIGEST in dockerfile
    assert PYTHON_ATTESTATION_DIGEST not in dockerfile
    assert "https://download.pytorch.org/whl/cpu" in dockerfile
    assert "cuda" not in dockerfile.casefold()
    assert "HOME=/tmp" in dockerfile
    assert "src/enterprise_ai_platform/__init__.py" in dockerfile
    assert "USER 10001:10001" in dockerfile


def test_direct_dependency_pins_and_build_context_are_exact() -> None:
    pins = tuple(REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines())
    assert pins == (
        "huggingface-hub==1.16.1",
        "pydantic==2.13.4",
        "pypdf==6.16.2",
        "pytest==9.1.1",
        "PyYAML==6.0.3",
        "qdrant-client==1.19.0",
        "safetensors==0.8.0",
        "sentence-transformers==5.7.0",
        "tokenizers==0.22.2",
        "torch==2.13.0",
        "transformers==5.15.1",
    )
    patterns = tuple(DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines())
    assert patterns[0] == "**"
    assert "!src/enterprise_ai_platform/__init__.py" in patterns
    assert "!src/enterprise_ai_platform/retrieval/**" in patterns
    assert "!tests/feature/test_local_retrieval.py" in patterns
    assert "!tests/rollback/test_w2_004_local_rollback.py" in patterns
    assert all("docs" not in pattern for pattern in patterns)
    assert all("data/sample" not in pattern for pattern in patterns)
    assert "!tests/rollback/__init__.py" not in patterns


def test_every_runner_copy_source_exists_in_repository() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    copy_sources: list[str] = []

    for line in dockerfile.splitlines():
        tokens = line.strip().split()
        if not tokens or tokens[0] != "COPY":
            continue

        operands = tuple(token for token in tokens[1:] if not token.startswith("--"))
        assert len(operands) == 2
        copy_sources.append(operands[0])

    assert copy_sources
    assert [source for source in copy_sources if not (ROOT / source).exists()] == []


def test_cleanliness_commands_are_fixed_read_only_inventory_operations() -> None:
    forbidden_tokens = {
        "build",
        "create",
        "delete",
        "down",
        "exec",
        "prune",
        "pull",
        "push",
        "rm",
        "run",
        "start",
        "stop",
        "up",
    }
    assert READ_ONLY_COMMANDS
    assert all(not forbidden_tokens.intersection(command) for command in READ_ONLY_COMMANDS)
    assert exit_code(()) == 0
    assert exit_code((CheckResult("x", State.PROHIBITED, {}),)) == 1
    assert exit_code((CheckResult("x", State.INDETERMINATE, {}),)) == 1
