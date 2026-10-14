"""Validate and reconcile the bounded W6-004 OpenSearch FGAC role."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

import yaml  # type: ignore[import-untyped]

SCHEMA_VERSION = "w6-004.opensearch-security.v1"
ROLE_NAME = "enterprise_ai_ingestion"
INDEX_NAME = "enterprise_ai_sandbox"
BACKEND_ROLE_ARN = "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-ingestion"
CLUSTER_PERMISSIONS = ("indices:data/write/bulk",)
INDEX_PERMISSIONS = (
    "indices:admin/exists",
    "indices:admin/get",
    "indices:admin/mappings/get",
    "indices:admin/refresh",
    "indices:data/read/get",
    "indices:data/read/search",
    "indices:data/write/bulk*",
    "indices:data/write/delete/byquery",
    "indices:data/write/index*",
)
FORBIDDEN_PERMISSIONS = frozenset({"*", "cluster:*", "indices:*", "cluster_composite_ops"})
DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs/opensearch/security-roles.yaml"
ROLE_API = f"/_plugins/_security/api/roles/{ROLE_NAME}"
ROLE_MAPPING_API = f"/_plugins/_security/api/rolesmapping/{ROLE_NAME}"


class W6004OpenSearchSecurityError(ValueError):
    """Raised when the governed FGAC contract is absent or broader than approved."""


class OpenSearchTransport(Protocol):
    """Small transport contract used by the reconciliation logic and offline tests."""

    def perform_request(
        self,
        method: str,
        path: str,
        *,
        body: object | None = None,
    ) -> object: ...


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise W6004OpenSearchSecurityError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise W6004OpenSearchSecurityError(f"{label} must be a list")
    result = list(value)
    if not all(isinstance(item, str) and item for item in result):
        raise W6004OpenSearchSecurityError(f"{label} must contain non-empty strings")
    return cast(list[str], result)


def validate_security_config(value: object) -> dict[str, object]:
    """Validate an in-memory W6-004 OpenSearch security contract."""

    config = _mapping(value, "security configuration")
    if config.get("schema_version") != SCHEMA_VERSION:
        raise W6004OpenSearchSecurityError("unexpected OpenSearch security schema")
    if set(config) != {"schema_version", "roles", "role_mappings"}:
        raise W6004OpenSearchSecurityError("security configuration has unexpected fields")

    roles = _mapping(config["roles"], "roles")
    mappings = _mapping(config["role_mappings"], "role_mappings")
    if set(roles) != {ROLE_NAME} or set(mappings) != {ROLE_NAME}:
        raise W6004OpenSearchSecurityError("only the governed ingestion role is permitted")

    role = _mapping(roles[ROLE_NAME], ROLE_NAME)
    if set(role) != {"cluster_permissions", "index_permissions", "tenant_permissions"}:
        raise W6004OpenSearchSecurityError("ingestion role has unexpected fields")

    cluster_permissions = _string_list(role["cluster_permissions"], "cluster_permissions")
    if cluster_permissions != list(CLUSTER_PERMISSIONS):
        raise W6004OpenSearchSecurityError("cluster permissions differ from the exact contract")
    if FORBIDDEN_PERMISSIONS.intersection(cluster_permissions):
        raise W6004OpenSearchSecurityError("broad cluster permission is forbidden")

    index_permissions = role["index_permissions"]
    if not isinstance(index_permissions, list) or len(index_permissions) != 1:
        raise W6004OpenSearchSecurityError("exactly one index permission block is required")
    index_permission = _mapping(index_permissions[0], "index permission")
    expected_index_keys = {
        "index_patterns",
        "allowed_actions",
        "dls",
        "fls",
        "masked_fields",
    }
    if set(index_permission) != expected_index_keys:
        raise W6004OpenSearchSecurityError("index permission has unexpected fields")
    if _string_list(index_permission["index_patterns"], "index_patterns") != [INDEX_NAME]:
        raise W6004OpenSearchSecurityError("index pattern is not the governed exact index")

    allowed_actions = _string_list(index_permission["allowed_actions"], "allowed_actions")
    if allowed_actions != list(INDEX_PERMISSIONS):
        raise W6004OpenSearchSecurityError("index actions differ from the exact contract")
    if FORBIDDEN_PERMISSIONS.intersection(allowed_actions):
        raise W6004OpenSearchSecurityError("broad index permission is forbidden")
    if index_permission["dls"] != "":
        raise W6004OpenSearchSecurityError("document-level security must remain unset")
    if index_permission["fls"] != [] or index_permission["masked_fields"] != []:
        raise W6004OpenSearchSecurityError("field restrictions must match the reviewed contract")
    if role["tenant_permissions"] != []:
        raise W6004OpenSearchSecurityError("tenant permissions are not permitted")

    role_mapping = _mapping(mappings[ROLE_NAME], "ingestion role mapping")
    if set(role_mapping) != {"backend_roles", "hosts", "users"}:
        raise W6004OpenSearchSecurityError("ingestion role mapping has unexpected fields")
    if _string_list(role_mapping["backend_roles"], "backend_roles") != [BACKEND_ROLE_ARN]:
        raise W6004OpenSearchSecurityError("backend role differs from the approved IAM role")
    if role_mapping["hosts"] != [] or role_mapping["users"] != []:
        raise W6004OpenSearchSecurityError("hosts and internal users are not permitted")

    return config


def load_security_config(path: Path = DEFAULT_CONFIG) -> dict[str, object]:
    """Load and validate the exact W6-004 OpenSearch security contract."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise W6004OpenSearchSecurityError(f"unable to load {path}: {error}") from error
    return validate_security_config(raw)


def role_payload(config: Mapping[str, object]) -> dict[str, object]:
    """Return only fields accepted by the Amazon OpenSearch role API."""

    roles = _mapping(config["roles"], "roles")
    role = _mapping(roles[ROLE_NAME], ROLE_NAME)
    return {
        "cluster_permissions": role["cluster_permissions"],
        "index_permissions": role["index_permissions"],
        "tenant_permissions": role["tenant_permissions"],
    }


def role_mapping_payload(config: Mapping[str, object]) -> dict[str, object]:
    """Return only fields accepted by the Amazon OpenSearch role-mapping API."""

    mappings = _mapping(config["role_mappings"], "role_mappings")
    mapping = _mapping(mappings[ROLE_NAME], "ingestion role mapping")
    return {
        "backend_roles": mapping["backend_roles"],
        "hosts": mapping["hosts"],
        "users": mapping["users"],
    }


def _named_response(value: object, label: str) -> dict[str, object]:
    response = _mapping(value, f"{label} response")
    if label in response:
        return _mapping(response[label], label)
    return response


def _api_role_payload(value: object) -> dict[str, object]:
    role = _named_response(value, ROLE_NAME)
    return {
        "cluster_permissions": role.get("cluster_permissions", []),
        "index_permissions": role.get("index_permissions", []),
        "tenant_permissions": role.get("tenant_permissions", []),
    }


def _api_mapping_payload(value: object) -> dict[str, object]:
    mapping = _named_response(value, ROLE_NAME)
    return {
        "backend_roles": mapping.get("backend_roles", []),
        "hosts": mapping.get("hosts", []),
        "users": mapping.get("users", []),
    }


def _get_optional(transport: OpenSearchTransport, path: str) -> object | None:
    try:
        return transport.perform_request("GET", path)
    except Exception as error:
        if getattr(error, "status_code", None) == 404:
            return None
        raise


def reconcile_security(
    transport: OpenSearchTransport,
    config: Mapping[str, object],
    *,
    apply: bool,
) -> dict[str, str]:
    """Inspect or reconcile the exact role and mapping, then verify equality."""

    expected_role = role_payload(config)
    expected_mapping = role_mapping_payload(config)
    current_role_response = _get_optional(transport, ROLE_API)
    current_mapping_response = _get_optional(transport, ROLE_MAPPING_API)
    current_role = (
        _api_role_payload(current_role_response) if current_role_response is not None else None
    )
    current_mapping = (
        _api_mapping_payload(current_mapping_response)
        if current_mapping_response is not None
        else None
    )

    role_changed = current_role != expected_role
    mapping_changed = current_mapping != expected_mapping
    if (role_changed or mapping_changed) and not apply:
        raise W6004OpenSearchSecurityError(
            "live OpenSearch security configuration differs; --apply is required"
        )

    if role_changed:
        transport.perform_request("PUT", ROLE_API, body=expected_role)
    if mapping_changed:
        transport.perform_request("PUT", ROLE_MAPPING_API, body=expected_mapping)

    verified_role = _api_role_payload(transport.perform_request("GET", ROLE_API))
    verified_mapping = _api_mapping_payload(transport.perform_request("GET", ROLE_MAPPING_API))
    if verified_role != expected_role or verified_mapping != expected_mapping:
        raise W6004OpenSearchSecurityError("OpenSearch read-back verification failed")

    return {
        "role": ("CREATED" if current_role is None else "UPDATED" if role_changed else "UNCHANGED"),
        "role_mapping": (
            "CREATED" if current_mapping is None else "UPDATED" if mapping_changed else "UNCHANGED"
        ),
    }


def _client(endpoint: str, region: str) -> tuple[Any, OpenSearchTransport]:
    try:
        import boto3  # type: ignore[import-untyped]
        from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection
    except ImportError as error:
        raise W6004OpenSearchSecurityError(
            "boto3 and opensearch-py are required for live reconciliation"
        ) from error

    session = boto3.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None:
        raise W6004OpenSearchSecurityError("AWS credentials are unavailable")
    client = OpenSearch(
        hosts=[{"host": endpoint, "port": 443}],
        http_auth=AWSV4SignerAuth(credentials, region, "es"),
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=True,
        connection_class=RequestsHttpConnection,
        timeout=10,
        max_retries=0,
        retry_on_timeout=False,
        http_compress=True,
    )
    return client, cast(OpenSearchTransport, client.transport)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--endpoint")
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    config = load_security_config(args.config)
    print(f"CONFIG={args.config}")
    print(f"SCHEMA_VERSION={config['schema_version']}")
    print(f"ROLE={ROLE_NAME}")
    print(f"INDEX={INDEX_NAME}")
    print("CONFIG_VALIDATION=PASS")

    if args.validate_only:
        if args.apply or args.endpoint:
            parser.error("--validate-only cannot be combined with --endpoint or --apply")
        print("OPENSEARCH_MUTATION=NOT_RUN")
        return 0
    if not args.endpoint:
        parser.error("--endpoint is required unless --validate-only is used")

    client, transport = _client(args.endpoint, args.region)
    try:
        result = reconcile_security(transport, config, apply=args.apply)
    finally:
        client.close()

    print(f"ROLE_RESULT={result['role']}")
    print(f"ROLE_MAPPING_RESULT={result['role_mapping']}")
    changed = result["role"] != "UNCHANGED" or result["role_mapping"] != "UNCHANGED"
    print(f"OPENSEARCH_MUTATION={'EXECUTED' if changed else 'NOT_RUN'}")
    print("OPENSEARCH_SECURITY_RECONCILIATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
