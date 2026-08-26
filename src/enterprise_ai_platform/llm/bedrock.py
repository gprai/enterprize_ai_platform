"""Amazon Bedrock Runtime Converse adapter with bounded blocking execution."""

from __future__ import annotations

import asyncio
import math
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol, cast

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ReadTimeoutError,
)

from enterprise_ai_platform.json_contracts import defensive_json_copy
from enterprise_ai_platform.llm.errors import (
    LLMAuthenticationError,
    LLMAuthorizationError,
    LLMError,
    LLMMalformedResponseError,
    LLMThrottlingError,
    LLMTimeoutError,
    LLMUnavailableError,
    LLMValidationError,
)
from enterprise_ai_platform.llm.models import (
    ChatRequest,
    ChatResponse,
    ChatRole,
    StopReason,
    ToolCall,
    Usage,
)
from enterprise_ai_platform.llm.provider import (
    PROCESS_WIDE_PROVIDER_CALL_GATE,
    ProviderCallGate,
    ProviderWorkerCancelledError,
    ProviderWorkerTimeoutError,
    run_blocking_provider_call,
)

CONNECT_TIMEOUT_SECONDS = 3
READ_TIMEOUT_SECONDS = 20
OUTER_TIMEOUT_SECONDS = 30.0
MAX_APPLICATION_ATTEMPTS = 2
MIN_RETRY_JITTER_SECONDS = 0.10
MAX_RETRY_JITTER_SECONDS = 0.25

_THROTTLE_CODES = frozenset({"ThrottlingException", "TooManyRequestsException"})
_UNAVAILABLE_CODES = frozenset(
    {
        "InternalServerException",
        "ModelNotReadyException",
        "ServiceUnavailableException",
    }
)
_TIMEOUT_CODES = frozenset({"ModelTimeoutException"})
_AUTHORIZATION_CODES = frozenset(
    {"AccessDeniedException", "UnauthorizedException"}
)
_AUTHENTICATION_CODES = frozenset(
    {"ExpiredTokenException", "InvalidSignatureException", "UnrecognizedClientException"}
)
_VALIDATION_CODES = frozenset(
    {"ResourceNotFoundException", "ValidationException", "ModelErrorException"}
)
_STOP_REASONS = frozenset(
    {
        "end_turn",
        "tool_use",
        "max_tokens",
        "stop_sequence",
        "guardrail_intervened",
        "content_filtered",
        "model_context_window_exceeded",
    }
)


class BedrockRuntimeClient(Protocol):
    def converse(self, **kwargs: object) -> Mapping[str, object]:
        """Call the Bedrock Runtime Converse API."""

        ...


BedrockClientFactory = Callable[[str, Config], BedrockRuntimeClient]
MonotonicClock = Callable[[], float]
AsyncSleep = Callable[[float], Awaitable[None]]
JitterSource = Callable[[], float]


def _default_client_factory(region: str, config: Config) -> BedrockRuntimeClient:
    import boto3  # type: ignore[import-untyped]

    return cast(
        BedrockRuntimeClient,
        boto3.client("bedrock-runtime", region_name=region, config=config),
    )


def _bedrock_config() -> Config:
    return Config(
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        read_timeout=READ_TIMEOUT_SECONDS,
        retries={"mode": "standard", "total_max_attempts": 1},
    )


def _default_jitter() -> float:
    return secrets.SystemRandom().uniform(
        MIN_RETRY_JITTER_SECONDS,
        MAX_RETRY_JITTER_SECONDS,
    )


def _client_error_code(error: ClientError) -> str:
    response = error.response
    if not isinstance(response, Mapping):
        return ""
    details = response.get("Error")
    if not isinstance(details, Mapping):
        return ""
    code = details.get("Code")
    return code if isinstance(code, str) else ""


def _is_retryable(error: BaseException) -> bool:
    if isinstance(error, (ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError)):
        return True
    return isinstance(error, ClientError) and _client_error_code(error) in (
        _THROTTLE_CODES | _TIMEOUT_CODES | _UNAVAILABLE_CODES
    )


def _normalized_error(error: BaseException) -> LLMError:
    if isinstance(error, (NoCredentialsError, PartialCredentialsError)):
        return LLMAuthenticationError()
    if isinstance(error, (ConnectTimeoutError, ReadTimeoutError)):
        return LLMTimeoutError()
    if isinstance(error, EndpointConnectionError):
        return LLMUnavailableError()
    if isinstance(error, ClientError):
        code = _client_error_code(error)
        if code in _AUTHENTICATION_CODES:
            return LLMAuthenticationError()
        if code in _AUTHORIZATION_CODES:
            return LLMAuthorizationError()
        if code in _THROTTLE_CODES:
            return LLMThrottlingError()
        if code in _TIMEOUT_CODES:
            return LLMTimeoutError()
        if code in _VALIDATION_CODES:
            return LLMValidationError()
        return LLMUnavailableError()
    return LLMUnavailableError()


def _strict_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LLMMalformedResponseError
    return value


def _parse_usage(raw_usage: object) -> Usage | None:
    if raw_usage is None:
        return None
    if not isinstance(raw_usage, Mapping):
        raise LLMMalformedResponseError
    try:
        return Usage(
            input_tokens=_strict_int(raw_usage["inputTokens"]),
            output_tokens=_strict_int(raw_usage["outputTokens"]),
            total_tokens=_strict_int(raw_usage["totalTokens"]),
            estimated_cost_usd=None,
        )
    except (KeyError, TypeError, ValueError):
        raise LLMMalformedResponseError from None


def _parse_response(raw_response: object) -> ChatResponse:
    if not isinstance(raw_response, Mapping):
        raise LLMMalformedResponseError
    output = raw_response.get("output")
    if not isinstance(output, Mapping):
        raise LLMMalformedResponseError
    message = output.get("message")
    if not isinstance(message, Mapping):
        raise LLMMalformedResponseError
    if message.get("role") != "assistant":
        raise LLMMalformedResponseError
    content = message.get("content")
    if not isinstance(content, list) or not content:
        raise LLMMalformedResponseError

    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in content:
        if not isinstance(block, Mapping):
            raise LLMMalformedResponseError
        has_text = "text" in block
        has_tool_use = "toolUse" in block
        if has_text == has_tool_use:
            raise LLMMalformedResponseError
        if has_text:
            text = block["text"]
            if not isinstance(text, str):
                raise LLMMalformedResponseError
            text_parts.append(text)
            continue
        tool_use = block.get("toolUse")
        if not isinstance(tool_use, Mapping):
            raise LLMMalformedResponseError
        identifier = tool_use.get("toolUseId")
        name = tool_use.get("name")
        arguments = tool_use.get("input")
        if (
            not isinstance(identifier, str)
            or not isinstance(name, str)
            or not isinstance(arguments, dict)
        ):
            raise LLMMalformedResponseError
        copied_arguments = defensive_json_copy(arguments)
        if not isinstance(copied_arguments, dict):
            raise LLMMalformedResponseError
        try:
            tool_calls.append(
                ToolCall(
                    tool_call_id=identifier,
                    name=name,
                    arguments=copied_arguments,
                )
            )
        except ValueError:
            raise LLMMalformedResponseError from None

    stop_reason = raw_response.get("stopReason")
    if not isinstance(stop_reason, str) or stop_reason not in _STOP_REASONS:
        raise LLMMalformedResponseError
    try:
        return ChatResponse(
            text="".join(text_parts),
            tool_calls=tuple(tool_calls),
            usage=_parse_usage(raw_response.get("usage")),
            stop_reason=cast(StopReason, stop_reason),
        )
    except ValueError:
        raise LLMMalformedResponseError from None


def _to_converse_request(request: ChatRequest, model_id: str) -> dict[str, object]:
    system: list[dict[str, str]] = []
    messages: list[dict[str, object]] = []
    for message in request.messages:
        if message.role is ChatRole.SYSTEM:
            system.append({"text": message.content})
        else:
            messages.append(
                {"role": message.role.value, "content": [{"text": message.content}]}
            )
    for result in request.tool_results:
        copied_content = defensive_json_copy(result.content)
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "toolResult": {
                            "toolUseId": result.tool_call_id,
                            "content": [{"json": copied_content}],
                            "status": "error" if result.is_error else "success",
                        }
                    }
                ],
            }
        )
    if not messages:
        raise LLMValidationError

    payload: dict[str, object] = {
        "modelId": model_id,
        "messages": messages,
        "inferenceConfig": {"maxTokens": request.max_output_tokens},
    }
    if system:
        payload["system"] = system
    if request.tools:
        tools: list[dict[str, object]] = []
        for tool in request.tools:
            schema = defensive_json_copy(tool.input_schema)
            if not isinstance(schema, dict):
                raise LLMValidationError
            tools.append(
                {
                    "toolSpec": {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": {"json": schema},
                    }
                }
            )
        payload["toolConfig"] = {"tools": tools}
    return payload


class BedrockLLMProvider:
    """Lazy Converse-only adapter; construction performs no AWS activity."""

    def __init__(
        self,
        *,
        model_id: str,
        region: str,
        client: BedrockRuntimeClient | None = None,
        client_factory: BedrockClientFactory = _default_client_factory,
        call_gate: ProviderCallGate = PROCESS_WIDE_PROVIDER_CALL_GATE,
        monotonic: MonotonicClock = time.monotonic,
        sleep: AsyncSleep = asyncio.sleep,
        jitter: JitterSource = _default_jitter,
    ) -> None:
        if not model_id.strip() or not region.strip():
            raise LLMValidationError
        self._model_id = model_id
        self._region = region
        self._client = client
        self._client_factory = client_factory
        self._call_gate = call_gate
        self._monotonic = monotonic
        self._sleep = sleep
        self._jitter = jitter
        self._client_lock = threading.Lock()

    def _get_client(self) -> BedrockRuntimeClient:
        client = self._client
        if client is not None:
            return client
        with self._client_lock:
            client = self._client
            if client is None:
                client = self._client_factory(self._region, _bedrock_config())
                self._client = client
            return client

    async def chat(self, request: ChatRequest) -> ChatResponse:
        payload = _to_converse_request(request, self._model_id)
        started = self._monotonic()

        for attempt in range(MAX_APPLICATION_ATTEMPTS):
            remaining = OUTER_TIMEOUT_SECONDS - (self._monotonic() - started)
            if remaining <= 0:
                raise LLMTimeoutError
            attempt_timeout = min(float(READ_TIMEOUT_SECONDS), remaining)

            def invoke() -> Mapping[str, object]:
                return self._get_client().converse(**payload)

            try:
                raw_response = await run_blocking_provider_call(
                    invoke,
                    gate=self._call_gate,
                    timeout_seconds=attempt_timeout,
                )
            except ProviderWorkerTimeoutError:
                raise LLMTimeoutError from None
            except ProviderWorkerCancelledError:
                raise asyncio.CancelledError from None
            except asyncio.CancelledError:
                raise
            except Exception as error:
                if attempt == 0 and _is_retryable(error):
                    delay = self._jitter()
                    if (
                        not math.isfinite(delay)
                        or delay < MIN_RETRY_JITTER_SECONDS
                        or delay > MAX_RETRY_JITTER_SECONDS
                    ):
                        raise LLMValidationError from None
                    if delay >= OUTER_TIMEOUT_SECONDS - (self._monotonic() - started):
                        raise LLMTimeoutError from None
                    await self._sleep(delay)
                    continue
                raise _normalized_error(error) from None

            response = _parse_response(raw_response)
            if self._monotonic() - started > OUTER_TIMEOUT_SECONDS:
                raise LLMTimeoutError
            return response

        raise LLMUnavailableError
