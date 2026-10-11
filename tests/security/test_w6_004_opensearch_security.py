from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from tools.w6_004_opensearch_security import (
    BACKEND_ROLE_ARN,
    CLUSTER_PERMISSIONS,
    INDEX_NAME,
    INDEX_PERMISSIONS,
    ROLE_API,
    ROLE_MAPPING_API,
    ROLE_NAME,
    W6004OpenSearchSecurityError,
    load_security_config,
    reconcile_security,
    role_mapping_payload,
    role_payload,
    validate_security_config,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/opensearch/security-roles.yaml"


def test_ingestion_role_has_exact_bounded_permissions() -> None:
    config = load_security_config(CONFIG)
    role = role_payload(config)
    mapping = role_mapping_payload(config)

    assert role["cluster_permissions"] == list(CLUSTER_PERMISSIONS)
    index_permissions = role["index_permissions"]
    assert isinstance(index_permissions, list)
    assert index_permissions[0]["index_patterns"] == [INDEX_NAME]
    assert index_permissions[0]["allowed_actions"] == list(INDEX_PERMISSIONS)
    assert role["tenant_permissions"] == []
    assert mapping == {
        "backend_roles": [BACKEND_ROLE_ARN],
        "hosts": [],
        "users": [],
    }


@pytest.mark.parametrize(
    "permission",
    ["*", "cluster:*", "indices:*", "cluster_composite_ops"],
)
def test_broad_cluster_permissions_are_rejected(permission: str) -> None:
    config = load_security_config(CONFIG)
    changed = deepcopy(config)
    changed["roles"][ROLE_NAME]["cluster_permissions"] = [permission]

    with pytest.raises(W6004OpenSearchSecurityError, match="cluster permissions"):
        validate_security_config(changed)


def test_unrelated_index_is_rejected() -> None:
    config = load_security_config(CONFIG)
    changed = deepcopy(config)
    changed["roles"][ROLE_NAME]["index_permissions"][0]["index_patterns"] = ["unapproved_index"]

    with pytest.raises(W6004OpenSearchSecurityError, match="governed exact index"):
        validate_security_config(changed)


def test_unrelated_backend_role_is_rejected() -> None:
    config = load_security_config(CONFIG)
    changed = deepcopy(config)
    changed["role_mappings"][ROLE_NAME]["backend_roles"] = [
        "arn:aws:iam::526338061652:role/unapproved"
    ]

    with pytest.raises(W6004OpenSearchSecurityError, match="approved IAM role"):
        validate_security_config(changed)


def test_role_payload_excludes_response_metadata() -> None:
    payload = role_payload(load_security_config(CONFIG))

    assert set(payload) == {
        "cluster_permissions",
        "index_permissions",
        "tenant_permissions",
    }
    assert "hidden" not in payload
    assert "reserved" not in payload
    assert "static" not in payload


class FakeNotFoundError(Exception):
    status_code = 404


class FakeTransport:
    def __init__(
        self,
        role: dict[str, object] | None,
        mapping: dict[str, object] | None,
    ) -> None:
        self.role = deepcopy(role)
        self.mapping = deepcopy(mapping)
        self.puts: list[tuple[str, object]] = []

    def perform_request(
        self,
        method: str,
        path: str,
        *,
        body: object | None = None,
    ) -> object:
        if method == "GET" and path == ROLE_API:
            if self.role is None:
                raise FakeNotFoundError
            return {ROLE_NAME: deepcopy(self.role)}
        if method == "GET" and path == ROLE_MAPPING_API:
            if self.mapping is None:
                raise FakeNotFoundError
            return {ROLE_NAME: deepcopy(self.mapping)}
        if method == "PUT" and path == ROLE_API:
            assert isinstance(body, dict)
            self.role = deepcopy(body)
            self.puts.append((path, deepcopy(body)))
            return {"status": "OK"}
        if method == "PUT" and path == ROLE_MAPPING_API:
            assert isinstance(body, dict)
            self.mapping = deepcopy(body)
            self.puts.append((path, deepcopy(body)))
            return {"status": "OK"}
        raise AssertionError(f"unexpected request: {method} {path}")


def test_compliant_role_is_verified_without_mutation() -> None:
    config = load_security_config(CONFIG)
    transport = FakeTransport(role_payload(config), role_mapping_payload(config))

    result = reconcile_security(transport, config, apply=False)

    assert result == {"role": "UNCHANGED", "role_mapping": "UNCHANGED"}
    assert transport.puts == []


def test_drift_requires_explicit_apply() -> None:
    config = load_security_config(CONFIG)
    drifted_role = role_payload(config)
    drifted_role["cluster_permissions"] = []
    transport = FakeTransport(drifted_role, role_mapping_payload(config))

    with pytest.raises(W6004OpenSearchSecurityError, match="--apply is required"):
        reconcile_security(transport, config, apply=False)

    assert transport.puts == []


def test_apply_repairs_role_and_verifies_read_back() -> None:
    config = load_security_config(CONFIG)
    drifted_role = role_payload(config)
    drifted_role["cluster_permissions"] = []
    transport = FakeTransport(drifted_role, role_mapping_payload(config))

    result = reconcile_security(transport, config, apply=True)

    assert result == {"role": "UPDATED", "role_mapping": "UNCHANGED"}
    assert transport.puts == [(ROLE_API, role_payload(config))]


def test_apply_creates_missing_role_and_mapping() -> None:
    config = load_security_config(CONFIG)
    transport = FakeTransport(None, None)

    result = reconcile_security(transport, config, apply=True)

    assert result == {"role": "CREATED", "role_mapping": "CREATED"}
    assert transport.puts == [
        (ROLE_API, role_payload(config)),
        (ROLE_MAPPING_API, role_mapping_payload(config)),
    ]
