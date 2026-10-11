"""Typed, offline preparation of fresh W5-004 plan request artifacts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from .contracts import Action, ContractError, validate_aws_account_id, validate_aws_region
from .lifecycle_io import (
    canonical_json_bytes,
    decode_json_strict,
    decode_operational_record,
    decode_record,
    ensure_external_path,
    remove_private_operation_outputs,
    reserve_operation_directory,
    sha256_bytes,
    sha256_file,
    validate_original_ancestors,
    write_canonical_json_atomic,
    write_private_bytes_exclusive,
)
from .lifecycle_models import (
    ChangeProfile,
    IdentityBundle,
    RecoveryProfile,
    ReviewRequest,
    RuntimeConfiguration,
)

EXPECTED_ACCOUNT = "526338061652"
EXPECTED_REGION = "ap-southeast-1"
EXPECTED_PRINCIPAL = "arn:aws:iam::526338061652:user/finopsinfra"
EXPECTED_OPERATION_ID = "saved-plan-009"
EXPECTED_PARENT = "consolidated-remediation-001"
EXPECTED_HEAD = "78576879b2c1d13507680872f471345c7b9b6be0"  # pragma: allowlist secret
EXPECTED_SOURCE_MEMBERS = 518
EXPECTED_PROTECTED_MEMBERS = 504
OWNER_CONFIRMATION_SCHEMA = "w5-004.plan-owner-confirmation.v1"
STATE_EVIDENCE_SCHEMA = "w5-004.plan-state-evidence.v1"
PREPARATION_DIRECTORY = "saved-plan-009-preparation"
VARIABLES_EXAMPLE = Path("infra/environments/sandbox/terraform.tfvars.example")
BACKEND_EXAMPLE = Path("infra/environments/sandbox/backend.hcl.example")


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_OBJECT_REQUIRED")
    return value


def _required_string(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.casefold()
        in {
            "todo",
            "placeholder",
            "changeme",
        }
    ):
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_REQUIRED")
    return value


def _required_hash(value: object, name: str) -> str:
    text = _required_string(value, name).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_HASH_INVALID")
    return text


def _exact_keys(value: Mapping[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_FIELDS_INVALID")


def _typed[T](value: object, model: type[T], name: str) -> T:
    try:
        return decode_record(_mapping(value, name), model)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_INVALID") from exc


class _HclLiteralReader:
    """Parse only the inert literal subset used by the two approved examples."""

    def __init__(self, text: str) -> None:
        lines: list[str] = []
        for line in text.splitlines():
            quoted = False
            escaped = False
            kept: list[str] = []
            for character in line:
                if character == "#" and not quoted:
                    break
                kept.append(character)
                if character == '"' and not escaped:
                    quoted = not quoted
                escaped = character == "\\" and not escaped
                if character != "\\":
                    escaped = False
            lines.append("".join(kept))
        self.text = "\n".join(lines)
        self.offset = 0

    def _space(self) -> None:
        while self.offset < len(self.text) and (
            self.text[self.offset].isspace() or self.text[self.offset] == ","
        ):
            self.offset += 1

    def _identifier(self) -> str:
        self._space()
        start = self.offset
        while self.offset < len(self.text) and (
            self.text[self.offset].isalnum() or self.text[self.offset] in "_-"
        ):
            self.offset += 1
        if start == self.offset:
            raise ContractError("PLAN_ARTIFACT_HCL_IDENTIFIER_INVALID")
        return self.text[start : self.offset]

    def _expect(self, token: str) -> None:
        self._space()
        if not self.text.startswith(token, self.offset):
            raise ContractError("PLAN_ARTIFACT_HCL_STRUCTURE_INVALID")
        self.offset += len(token)

    def _mapping_key(self) -> str:
        self._space()
        if self.offset < len(self.text) and self.text[self.offset] == '"':
            value = self._value()
            if not isinstance(value, str) or not value:
                raise ContractError("PLAN_ARTIFACT_HCL_IDENTIFIER_INVALID")
            return value
        return self._identifier()

    def _value(self) -> object:
        self._space()
        if self.offset >= len(self.text):
            raise ContractError("PLAN_ARTIFACT_HCL_VALUE_REQUIRED")
        character = self.text[self.offset]
        if character == '"':
            try:
                value, end = json.JSONDecoder().raw_decode(self.text[self.offset :])
            except json.JSONDecodeError as exc:
                raise ContractError("PLAN_ARTIFACT_HCL_STRING_INVALID") from exc
            self.offset += end
            return value
        if character == "[":
            self.offset += 1
            list_values: list[object] = []
            while True:
                self._space()
                if self.offset < len(self.text) and self.text[self.offset] == "]":
                    self.offset += 1
                    return list_values
                list_values.append(self._value())
        if character == "{":
            self.offset += 1
            mapping_values: dict[str, object] = {}
            while True:
                self._space()
                if self.offset < len(self.text) and self.text[self.offset] == "}":
                    self.offset += 1
                    return mapping_values
                key = self._mapping_key()
                if key in mapping_values:
                    raise ContractError("PLAN_ARTIFACT_HCL_DUPLICATE_KEY")
                self._expect("=")
                mapping_values[key] = self._value()
        start = self.offset
        while (
            self.offset < len(self.text)
            and not self.text[self.offset].isspace()
            and self.text[self.offset] not in ",]}"
        ):
            self.offset += 1
        literal = self.text[start : self.offset]
        if literal in {"true", "false"}:
            return literal == "true"
        if literal == "null":
            return None
        try:
            return int(literal)
        except ValueError as exc:
            raise ContractError("PLAN_ARTIFACT_HCL_LITERAL_INVALID") from exc

    def parse(self) -> dict[str, object]:
        values: dict[str, object] = {}
        while True:
            self._space()
            if self.offset == len(self.text):
                return values
            key = self._identifier()
            if key in values:
                raise ContractError("PLAN_ARTIFACT_HCL_DUPLICATE_KEY")
            self._expect("=")
            values[key] = self._value()


def _hcl_literals(path: Path) -> dict[str, object]:
    try:
        return _HclLiteralReader(path.read_text(encoding="utf-8")).parse()
    except UnicodeError as exc:
        raise ContractError("PLAN_ARTIFACT_HCL_ENCODING_INVALID") from exc


def _placeholder_paths(value: object, prefix: str = "") -> set[str]:
    if isinstance(value, Mapping):
        result: set[str] = set()
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractError("PLAN_ARTIFACT_EXAMPLE_KEY_INVALID")
            path = f"{prefix}.{key}" if prefix else key
            result.update(_placeholder_paths(child, path))
        return result
    if isinstance(value, list):
        result = set()
        for index, child in enumerate(value):
            result.update(_placeholder_paths(child, f"{prefix}[{index}]"))
        return result
    return {prefix} if isinstance(value, str) and value.casefold().startswith("todo") else set()


def _contains_historical_reference(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_historical_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_historical_reference(child) for child in value)
    return isinstance(value, str) and "saved-plan-007" in value.casefold()


def _apply_overrides(
    value: dict[str, object], overrides: Mapping[str, object]
) -> dict[str, object]:
    placeholders = _placeholder_paths(value)
    if set(overrides) != placeholders:
        raise ContractError("PLAN_ARTIFACT_OWNER_OVERRIDES_INCOMPLETE")
    result = deepcopy(value)
    for dotted, replacement in overrides.items():
        if not isinstance(replacement, (str, int, bool)) or (
            isinstance(replacement, str) and replacement.casefold().startswith("todo")
        ):
            raise ContractError("PLAN_ARTIFACT_OWNER_OVERRIDE_INVALID")
        parts = dotted.split(".")
        target: dict[str, object] = result
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                raise ContractError("PLAN_ARTIFACT_OWNER_OVERRIDE_PATH_INVALID")
            target = child
        target[parts[-1]] = replacement
    if _placeholder_paths(result):
        raise ContractError("PLAN_ARTIFACT_UNRESOLVED_PLACEHOLDER")
    return result


def _backend_bytes(values: Mapping[str, object]) -> bytes:
    names = ("bucket", "key", "region", "use_lockfile", "encrypt", "kms_key_id")
    if "dynamodb_table" in values:
        raise ContractError("PLAN_ARTIFACT_BACKEND_LOCKFILE_REQUIRED")
    _exact_keys(values, set(names), "backend")
    if values.get("use_lockfile") is not True:
        raise ContractError("PLAN_ARTIFACT_BACKEND_LOCKFILE_REQUIRED")
    lines: list[str] = []
    for name in names:
        value = values[name]
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, str) and value:
            rendered = json.dumps(value, ensure_ascii=False)
        else:
            raise ContractError("PLAN_ARTIFACT_BACKEND_VALUE_INVALID")
        lines.append(f"{name} = {rendered}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _canonical_operation_root(external_root: Path) -> Path:
    return external_root / EXPECTED_PARENT / EXPECTED_OPERATION_ID


def _validate_timestamp(value: object, name: str) -> None:
    text = _required_string(value, name)
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ContractError(f"PLAN_ARTIFACT_{name.upper()}_TIMESTAMP_NOT_UTC")


def _validate_owner_bindings(value: object, request: ReviewRequest) -> None:
    bindings = _mapping(value, "owner_bindings")
    _exact_keys(
        bindings,
        {
            "account_id",
            "region",
            "principal_arn",
            "environment",
            "target",
            "lifecycle_ceiling_usd",
            "source_member_count",
            "protected_member_count",
            "source_sha256",
            "policy_sha256",
            "protected_sha256",
            "tools_sha256",
            "state_content_sha256",
            "state_lineage",
            "state_serial",
            "expiry_authority",
            "cost_authority",
        },
        "owner_bindings",
    )
    account = _required_string(bindings.get("account_id"), "account_id")
    if validate_aws_account_id(account) != EXPECTED_ACCOUNT:
        raise ContractError("PLAN_ARTIFACT_ACCOUNT_SCOPE_MISMATCH")
    if validate_aws_region(_required_string(bindings.get("region"), "region")) != EXPECTED_REGION:
        raise ContractError("PLAN_ARTIFACT_REGION_SCOPE_MISMATCH")
    if _required_string(bindings.get("principal_arn"), "principal_arn") != EXPECTED_PRINCIPAL:
        raise ContractError("PLAN_ARTIFACT_PRINCIPAL_SCOPE_MISMATCH")
    if _required_string(bindings.get("environment"), "environment") != "sandbox":
        raise ContractError("PLAN_ARTIFACT_ENVIRONMENT_SCOPE_MISMATCH")
    if _required_string(bindings.get("target"), "target") != "platform":
        raise ContractError("PLAN_ARTIFACT_TARGET_SCOPE_MISMATCH")
    ceiling = _required_string(bindings.get("lifecycle_ceiling_usd"), "lifecycle_ceiling_usd")
    if ceiling != "3.00":
        raise ContractError("PLAN_ARTIFACT_LIFECYCLE_CEILING_MISMATCH")
    if (
        bindings.get("source_member_count") != EXPECTED_SOURCE_MEMBERS
        or bindings.get("protected_member_count") != EXPECTED_PROTECTED_MEMBERS
    ):
        raise ContractError("PLAN_ARTIFACT_SOURCE_INVENTORY_MISMATCH")
    source_hash = _required_hash(bindings.get("source_sha256"), "source_sha256")
    if source_hash != request.approved_identities.working_sha256:
        raise ContractError("PLAN_ARTIFACT_SOURCE_IDENTITY_MISMATCH")
    _required_hash(bindings.get("policy_sha256"), "policy_sha256")
    _required_hash(bindings.get("protected_sha256"), "protected_sha256")
    _required_hash(bindings.get("tools_sha256"), "tools_sha256")
    _required_hash(bindings.get("state_content_sha256"), "state_content_sha256")
    lineage = _required_string(bindings.get("state_lineage"), "state_lineage")
    if lineage.casefold() in {"unknown", "unavailable"}:
        raise ContractError("PLAN_ARTIFACT_STATE_LINEAGE_REQUIRED")
    serial = bindings.get("state_serial")
    if not isinstance(serial, int) or serial < 0:
        raise ContractError("PLAN_ARTIFACT_STATE_SERIAL_REQUIRED")
    expiry = _mapping(bindings.get("expiry_authority"), "expiry_authority")
    _exact_keys(expiry, {"status", "value"}, "expiry_authority")
    if _required_string(expiry.get("status"), "expiry_authority_status") != "OWNER_SUPPLIED":
        raise ContractError("PLAN_ARTIFACT_EXPIRY_AUTHORITY_REQUIRED")
    _validate_timestamp(expiry.get("value"), "expiry")
    if expiry.get("value") != request.profile.expires_at:
        raise ContractError("PLAN_ARTIFACT_EXPIRY_BINDING_MISMATCH")
    cost = _mapping(bindings.get("cost_authority"), "cost_authority")
    _exact_keys(
        cost,
        {"status", "currency", "lifecycle_ceiling_usd", "scope"},
        "cost_authority",
    )
    if _required_string(cost.get("status"), "cost_authority_status") != "OWNER_SUPPLIED":
        raise ContractError("PLAN_ARTIFACT_COST_AUTHORITY_REQUIRED")
    if (
        cost.get("currency") != "USD"
        or cost.get("lifecycle_ceiling_usd") != "3.00"
        or cost.get("scope") != "TOTAL_CYCLE"
    ):
        raise ContractError("PLAN_ARTIFACT_COST_AUTHORITY_MISMATCH")


def _validate_request(request: ReviewRequest, operation_root: Path, external_root: Path) -> None:
    if request.operation_id != EXPECTED_OPERATION_ID:
        raise ContractError("PLAN_ARTIFACT_OPERATION_ID_MISMATCH")
    if request.action is not Action.PLATFORM_APPLY or request.target != "platform":
        raise ContractError("PLAN_ARTIFACT_PLATFORM_APPLY_REQUIRED")
    if request.environment != "sandbox":
        raise ContractError("PLAN_ARTIFACT_ENVIRONMENT_MISMATCH")
    if request.profile.action is not Action.PLATFORM_APPLY:
        raise ContractError("PLAN_ARTIFACT_PROFILE_ACTION_MISMATCH")
    if request.profile.profile not in {ChangeProfile.INITIAL, ChangeProfile.PARTIAL_RECOVERY}:
        raise ContractError("PLAN_ARTIFACT_PROFILE_NOT_RECOVERY")
    if not request.profile.rules:
        raise ContractError("PLAN_ARTIFACT_RESOURCE_RULES_REQUIRED")
    identities = request.approved_identities
    for name, value in (
        ("working_sha256", identities.working_sha256),
        ("index_sha256", identities.index_sha256),
        ("authorization_sha256", identities.authorization_sha256),
        ("governance_sha256", identities.governance_sha256),
        ("backend_sha256", identities.backend_sha256),
    ):
        _required_hash(value, name)
    if _required_string(identities.repository_head, "repository_head") != EXPECTED_HEAD:
        raise ContractError("PLAN_ARTIFACT_REPOSITORY_HEAD_MISMATCH")
    if not identities.tools or not identities.inputs:
        raise ContractError("PLAN_ARTIFACT_REQUEST_IDENTITIES_REQUIRED")
    for rule in request.profile.rules:
        unsafe = {"delete", "destroy", "replace", "import"}
        if any(action.casefold() in unsafe for action in rule.actions):
            raise ContractError("PLAN_ARTIFACT_UNSAFE_RESOURCE_ACTION")
        if any(token in rule.address.casefold() for token in ("tfstate", "tflock", "bootstrap")):
            raise ContractError("PLAN_ARTIFACT_BOOTSTRAP_SCOPE")
    _validate_timestamp(request.profile.expires_at, "profile_expiry")
    if operation_root != _canonical_operation_root(external_root):
        raise ContractError("PLAN_ARTIFACT_OPERATION_ROOT_MISMATCH")
    for path in (request.variables_path, request.backend_path):
        if "saved-plan-007" in path:
            raise ContractError("PLAN_ARTIFACT_HISTORICAL_INPUT_REUSE")


def _repository_example(
    supplied: Path,
    expected_relative: Path,
    expected_sha256: str,
    repository_root: Path,
) -> Path:
    expected = repository_root / expected_relative
    validate_original_ancestors(supplied)
    validate_original_ancestors(expected)
    try:
        if supplied.resolve(strict=True) != expected.resolve(strict=True):
            raise ContractError("PLAN_ARTIFACT_EXAMPLE_PATH_MISMATCH")
    except OSError as exc:
        raise ContractError("PLAN_ARTIFACT_EXAMPLE_PATH_UNAVAILABLE") from exc
    if sha256_file(expected) != expected_sha256.lower():
        raise ContractError("PLAN_ARTIFACT_EXAMPLE_HASH_MISMATCH")
    return expected


def prepare_owner_envelope(
    owner_confirmation: Path,
    owner_confirmation_sha256: str,
    state_evidence: Path,
    state_evidence_sha256: str,
    variables_example: Path,
    variables_example_sha256: str,
    backend_example: Path,
    backend_example_sha256: str,
    operation_root: Path,
    *,
    external_root: Path,
    repository_root: Path,
) -> tuple[tuple[str, str], ...]:
    """Construct typed fresh inputs and an owner envelope without invoking external tools."""
    root = ensure_external_path(operation_root, external_root, repository_root)
    if root != _canonical_operation_root(external_root):
        raise ContractError("PLAN_ARTIFACT_OPERATION_ROOT_MISMATCH")
    if root.exists():
        raise ContractError("PLAN_ARTIFACT_OPERATION_DIRECTORY_ALREADY_EXISTS")
    confirmation_path = ensure_external_path(owner_confirmation, external_root, repository_root)
    state_path = ensure_external_path(state_evidence, external_root, repository_root)
    if sha256_file(confirmation_path) != owner_confirmation_sha256.lower():
        raise ContractError("PLAN_ARTIFACT_OWNER_CONFIRMATION_HASH_MISMATCH")
    if sha256_file(state_path) != state_evidence_sha256.lower():
        raise ContractError("PLAN_ARTIFACT_STATE_EVIDENCE_HASH_MISMATCH")
    variables_source = _repository_example(
        variables_example,
        VARIABLES_EXAMPLE,
        variables_example_sha256,
        repository_root,
    )
    backend_source = _repository_example(
        backend_example,
        BACKEND_EXAMPLE,
        backend_example_sha256,
        repository_root,
    )
    confirmation = _mapping(
        decode_json_strict(confirmation_path.read_bytes()), "owner_confirmation"
    )
    if _contains_historical_reference(confirmation):
        raise ContractError("PLAN_ARTIFACT_HISTORICAL_INPUT_REUSE")
    _exact_keys(
        confirmation,
        {
            "schema_version",
            "operation_id",
            "account_id",
            "region",
            "principal_arn",
            "environment",
            "target",
            "variable_overrides",
            "profile",
            "approved_identities",
            "runtime",
            "owner_bindings",
        },
        "owner_confirmation",
    )
    if _required_string(confirmation["schema_version"], "confirmation_schema") != (
        OWNER_CONFIRMATION_SCHEMA
    ):
        raise ContractError("PLAN_ARTIFACT_OWNER_CONFIRMATION_SCHEMA_MISMATCH")
    fixed = {
        "operation_id": EXPECTED_OPERATION_ID,
        "account_id": EXPECTED_ACCOUNT,
        "region": EXPECTED_REGION,
        "principal_arn": EXPECTED_PRINCIPAL,
        "environment": "sandbox",
        "target": "platform",
    }
    if any(confirmation[name] != expected for name, expected in fixed.items()):
        raise ContractError("PLAN_ARTIFACT_OWNER_CONFIRMATION_SCOPE_MISMATCH")
    state = _mapping(decode_json_strict(state_path.read_bytes()), "state_evidence")
    if _contains_historical_reference(state):
        raise ContractError("PLAN_ARTIFACT_HISTORICAL_INPUT_REUSE")
    _exact_keys(
        state,
        {
            "schema_version",
            "operation_id",
            "account_id",
            "region",
            "environment",
            "target",
            "lineage",
            "serial",
            "content_sha256",
            "observed_at",
        },
        "state_evidence",
    )
    if state["schema_version"] != STATE_EVIDENCE_SCHEMA or any(
        state[name] != expected for name, expected in fixed.items() if name != "principal_arn"
    ):
        raise ContractError("PLAN_ARTIFACT_STATE_EVIDENCE_SCOPE_MISMATCH")
    state_lineage = _required_string(state["lineage"], "state_lineage")
    state_serial = state["serial"]
    if not isinstance(state_serial, int) or isinstance(state_serial, bool) or state_serial < 0:
        raise ContractError("PLAN_ARTIFACT_STATE_SERIAL_REQUIRED")
    state_content_sha256 = _required_hash(state["content_sha256"], "state_content_sha256")
    _validate_timestamp(state["observed_at"], "state_observed_at")

    variables = _hcl_literals(variables_source)
    variables = _apply_overrides(
        variables, _mapping(confirmation["variable_overrides"], "variable_overrides")
    )
    if (
        variables.get("aws_account_id") != EXPECTED_ACCOUNT
        or variables.get("aws_region") != EXPECTED_REGION
        or not isinstance(variables.get("mandatory_tags"), dict)
    ):
        raise ContractError("PLAN_ARTIFACT_VARIABLE_SCOPE_MISMATCH")
    tags = _mapping(variables["mandatory_tags"], "mandatory_tags")
    expiry = _required_string(tags.get("ExpiresAt"), "expires_at")
    _validate_timestamp(expiry, "expires_at")
    backend = _hcl_literals(backend_source)
    backend_payload = _backend_bytes(backend)
    if (
        backend.get("region") != EXPECTED_REGION
        or backend.get("bucket") != "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
        or backend.get("key") != "sandbox/platform.tfstate"
        or backend.get("use_lockfile") is not True
        or "dynamodb_table" in backend
        or backend.get("kms_key_id") != "alias/enterprise-ai-platform-sandbox-terraform-state"
        or backend.get("encrypt") is not True
    ):
        raise ContractError("PLAN_ARTIFACT_BACKEND_SCOPE_MISMATCH")

    profile = _typed(confirmation["profile"], RecoveryProfile, "recovery_profile")
    identities = _typed(confirmation["approved_identities"], IdentityBundle, "approved_identities")
    runtime = _typed(confirmation["runtime"], RuntimeConfiguration, "runtime")
    bindings = dict(_mapping(confirmation["owner_bindings"], "owner_bindings"))
    if profile.expires_at != expiry:
        raise ContractError("PLAN_ARTIFACT_EXPIRY_BINDING_MISMATCH")
    if (
        runtime.expected_state_lineage != state_lineage
        or runtime.expected_state_serial != state_serial
        or bindings.get("state_lineage") != state_lineage
        or bindings.get("state_serial") != state_serial
        or bindings.get("state_content_sha256") != state_content_sha256
    ):
        raise ContractError("PLAN_ARTIFACT_STATE_BINDING_MISMATCH")

    preparation_root = external_root / EXPECTED_PARENT / PREPARATION_DIRECTORY
    variables_path = preparation_root / "inputs" / "platform.tfvars.json"
    backend_path = preparation_root / "inputs" / "platform.backend.hcl"
    envelope_path = preparation_root / "owner-input.json"
    if preparation_root.exists():
        raise ContractError("PLAN_ARTIFACT_PREPARATION_DIRECTORY_ALREADY_EXISTS")
    variables_payload = canonical_json_bytes(variables)
    variables_sha256 = sha256_bytes(variables_payload)
    backend_sha256 = sha256_bytes(backend_payload)
    generated_inputs = (
        ("owner/confirmation.json", str(confirmation_path), owner_confirmation_sha256.lower()),
        ("owner/platform.backend.hcl", str(backend_path), backend_sha256),
        ("owner/platform.tfvars.json", str(variables_path), variables_sha256),
        ("owner/state-evidence.json", str(state_path), state_evidence_sha256.lower()),
    )
    reserved = {row[0] for row in generated_inputs}
    if any(row[0] in reserved for row in runtime.input_files):
        raise ContractError("PLAN_ARTIFACT_RUNTIME_INPUT_COLLISION")
    runtime = replace(runtime, input_files=tuple(sorted((*runtime.input_files, *generated_inputs))))
    runtime_hash = sha256_bytes(canonical_json_bytes(asdict(runtime)))
    identity_inputs = dict(identities.inputs)
    additions = {logical: digest for logical, _path, digest in generated_inputs}
    additions["runtime/configuration.json"] = runtime_hash
    if set(identity_inputs).intersection(additions):
        raise ContractError("PLAN_ARTIFACT_IDENTITY_INPUT_COLLISION")
    identity_inputs.update(additions)
    identities = replace(
        identities,
        inputs=tuple(sorted(identity_inputs.items())),
        backend_sha256=backend_sha256,
    )
    request = ReviewRequest(
        schema_version="w5-004.lifecycle.v2",
        operation_id=EXPECTED_OPERATION_ID,
        action=Action.PLATFORM_APPLY,
        target="platform",
        environment="sandbox",
        approved_identities=identities,
        profile=profile,
        variables_path=str(variables_path),
        variables_sha256=variables_sha256,
        backend_path=str(backend_path),
        backend_sha256=backend_sha256,
        operation_root=str(root),
    )
    _validate_request(request, root, external_root)
    _validate_owner_bindings(bindings, request)
    expiry_authority = _mapping(bindings.get("expiry_authority"), "expiry_authority")
    if expiry_authority.get("value") != expiry:
        raise ContractError("PLAN_ARTIFACT_EXPIRY_AUTHORITY_MISMATCH")
    outputs = (variables_path, backend_path, envelope_path)
    reserve_operation_directory(preparation_root, external_root, repository_root)
    try:
        variables_hash = write_canonical_json_atomic(
            variables_path,
            variables,
            allowed_root=external_root,
            repository_root=repository_root,
        )
        backend_hash = write_private_bytes_exclusive(
            backend_path,
            backend_payload,
            allowed_root=external_root,
            repository_root=repository_root,
        )
        envelope_hash = write_canonical_json_atomic(
            envelope_path,
            {
                "request": asdict(request),
                "runtime": asdict(runtime),
                "owner_bindings": bindings,
            },
            allowed_root=external_root,
            repository_root=repository_root,
        )
    except Exception:
        remove_private_operation_outputs(
            outputs,
            preparation_root,
            allowed_root=external_root,
            repository_root=repository_root,
        )
        raise
    if (variables_hash, backend_hash) != (variables_sha256, backend_sha256):
        remove_private_operation_outputs(
            outputs,
            preparation_root,
            allowed_root=external_root,
            repository_root=repository_root,
        )
        raise ContractError("PLAN_ARTIFACT_PREPARATION_IDENTITY_MISMATCH")
    return (
        (str(variables_path), variables_hash),
        (str(backend_path), backend_hash),
        (str(envelope_path), envelope_hash),
    )


def prepare_plan_artifacts(
    owner_input: Path,
    owner_input_sha256: str,
    operation_root: Path,
    *,
    external_root: Path,
    repository_root: Path,
) -> tuple[tuple[str, str], ...]:
    """Validate an explicit owner envelope and write fresh request/runtime JSON only."""
    owner_input = ensure_external_path(owner_input, external_root, repository_root)
    if sha256_file(owner_input) != owner_input_sha256.lower():
        raise ContractError("PLAN_ARTIFACT_OWNER_INPUT_HASH_MISMATCH")
    envelope = _mapping(decode_json_strict(owner_input.read_bytes()), "owner_input")
    request_raw = canonical_json_bytes(_mapping(envelope.get("request"), "request"))
    runtime_raw = canonical_json_bytes(_mapping(envelope.get("runtime"), "runtime"))
    request = decode_operational_record(request_raw, ReviewRequest)
    runtime = decode_operational_record(runtime_raw, RuntimeConfiguration)
    root = ensure_external_path(operation_root, external_root, repository_root)
    if root.exists():
        raise ContractError("PLAN_ARTIFACT_OPERATION_DIRECTORY_ALREADY_EXISTS")
    if request.operation_root != str(root):
        raise ContractError("PLAN_ARTIFACT_OPERATION_ROOT_BINDING_MISMATCH")
    _validate_request(request, root, external_root)
    _validate_owner_bindings(envelope.get("owner_bindings"), request)
    variables = ensure_external_path(Path(request.variables_path), external_root, repository_root)
    backend = ensure_external_path(Path(request.backend_path), external_root, repository_root)
    if sha256_file(variables) != request.variables_sha256:
        raise ContractError("PLAN_ARTIFACT_VARIABLES_HASH_MISMATCH")
    if sha256_file(backend) != request.backend_sha256:
        raise ContractError("PLAN_ARTIFACT_BACKEND_HASH_MISMATCH")
    bindings = _mapping(envelope.get("owner_bindings"), "owner_bindings")
    if _required_hash(bindings.get("backend_sha256"), "backend_sha256") != request.backend_sha256:
        raise ContractError("PLAN_ARTIFACT_BACKEND_IDENTITY_MISMATCH")
    state_lineage = _required_string(bindings.get("state_lineage"), "state_lineage")
    if runtime.expected_state_lineage != state_lineage:
        raise ContractError("PLAN_ARTIFACT_STATE_LINEAGE_MISMATCH")
    if runtime.expected_state_serial != bindings.get("state_serial"):
        raise ContractError("PLAN_ARTIFACT_STATE_SERIAL_MISMATCH")
    if runtime.cost_terms.operation_id != request.operation_id:
        raise ContractError("PLAN_ARTIFACT_COST_OPERATION_MISMATCH")
    if runtime.cost_terms.scope != "platform":
        raise ContractError("PLAN_ARTIFACT_COST_SCOPE_MISMATCH")
    if not runtime.input_files or not runtime.protected_files or not runtime.tools:
        raise ContractError("PLAN_ARTIFACT_RUNTIME_IDENTITIES_REQUIRED")
    reserve_operation_directory(root, external_root, repository_root)
    request_path = root / "inputs" / "request.json"
    runtime_path = root / "inputs" / "runtime.json"
    request_hash = write_canonical_json_atomic(
        request_path, asdict(request), allowed_root=external_root, repository_root=repository_root
    )
    runtime_hash = write_canonical_json_atomic(
        runtime_path, asdict(runtime), allowed_root=external_root, repository_root=repository_root
    )
    return ((str(request_path), request_hash), (str(runtime_path), runtime_hash))
