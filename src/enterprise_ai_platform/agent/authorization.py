"""Trusted same-tenant role checks for W4-002 agent operations."""

from __future__ import annotations

from enterprise_ai_platform.retrieval.models import AuthContext, Role

from .errors import AgentAuthorizationError
from .models import ToolKind
from .serialization import fingerprint, hash_identifier


def authorization_reference(auth_context: AuthContext) -> str:
    """Fingerprint only the immutable authority facts required by the agent."""

    return fingerprint(
        {
            "clearance": auth_context.clearance.value,
            "roles": sorted(role.value for role in auth_context.roles),
            "tenant_reference_sha256": hash_identifier(auth_context.tenant_id),
            "subject_reference_sha256": hash_identifier(auth_context.subject_id),
        }
    )


def require_start_authorized(auth_context: AuthContext) -> None:
    if not auth_context.roles.intersection({Role.READER, Role.ADMIN}):
        raise AgentAuthorizationError


def require_decision_authorized(auth_context: AuthContext) -> None:
    if Role.REVIEWER not in auth_context.roles:
        raise AgentAuthorizationError


def require_tool_authorized(auth_context: AuthContext, kind: ToolKind) -> None:
    required = Role.READER if kind is ToolKind.READ else Role.ADMIN
    if required not in auth_context.roles:
        raise AgentAuthorizationError


def require_approver_authorized(
    auth_context: AuthContext,
    *,
    tenant_reference_sha256: str,
    requester_reference_sha256: str,
) -> None:
    if Role.REVIEWER not in auth_context.roles:
        raise AgentAuthorizationError
    if hash_identifier(auth_context.tenant_id) != tenant_reference_sha256:
        raise AgentAuthorizationError
    if hash_identifier(auth_context.subject_id) == requester_reference_sha256:
        raise AgentAuthorizationError
