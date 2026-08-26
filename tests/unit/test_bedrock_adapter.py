"""Unit tests for the lazy, Converse-only Bedrock adapter."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Mapping

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from enterprise_ai_platform.llm.bedrock import BedrockLLMProvider
from enterprise_ai_platform.llm.errors import (
    LLMAuthenticationError,
    LLMMalformedResponseError,
    LLMThrottlingError,
    LLMTimeoutError,
)
from enterprise_ai_platform.llm.models import ChatMessage, ChatRequest, ChatRole, ToolSpec
from enterprise_ai_platform.llm.provider import (
    PROCESS_WIDE_PROVIDER_CALL_GATE,
    ProviderCallGate,
    ProviderWorkerTimeoutError,
)


def _request(*, with_tool: bool = False) -> ChatRequest:
    tools = (
        ToolSpec(
            name="lookup",
            description="Synthetic schema only",
            input_schema={"type": "object", "additionalProperties": False},
        ),
    ) if with_tool else ()
    return ChatRequest(
        messages=(
            ChatMessage(role=ChatRole.SYSTEM, content="Synthetic system instruction"),
            ChatMessage(role=ChatRole.USER, content="Synthetic question"),
        ),
        tools=tools,
        max_output_tokens=512,
    )


def _response(*, usage: object | None = None) -> dict[str, object]:
    return {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": '{"answer":"ok"}'}],
            }
        },
        "usage": usage
        or {"inputTokens": 4, "outputTokens": 3, "totalTokens": 7},
        "stopReason": "end_turn",
    }


class StubBedrockClient:
    def __init__(self, outcomes: list[Mapping[str, object] | BaseException]) -> None:
        self.outcomes = outcomes
        self.calls: list[dict[str, object]] = []

    def converse(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(dict(kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def test_client_is_lazy_and_botocore_retries_are_disabled() -> None:
    created: list[tuple[str, object]] = []
    client = StubBedrockClient([_response()])

    def factory(region: str, config: object) -> StubBedrockClient:
        created.append((region, config))
        return client

    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client_factory=factory,  # type: ignore[arg-type]
    )
    assert created == []

    response = asyncio.run(provider.chat(_request(with_tool=True)))

    assert response.usage is not None
    assert response.usage.total_tokens == 7
    assert len(created) == 1
    region, config = created[0]
    assert region == "ap-southeast-1"
    assert config.connect_timeout == 3  # type: ignore[attr-defined]
    assert config.read_timeout == 20  # type: ignore[attr-defined]
    assert config.retries == {  # type: ignore[attr-defined]
        "mode": "standard",
        "total_max_attempts": 1,
    }
    payload = client.calls[0]
    assert payload["modelId"] == "synthetic.model-v1"
    assert "toolConfig" in payload
    assert "invoke_model" not in repr(payload).casefold()


def test_one_completed_transient_failure_is_retried_without_real_sleep() -> None:
    throttled = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "sensitive"}},
        "Converse",
    )
    client = StubBedrockClient([throttled, _response()])
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=client,
        jitter=lambda: 0.10,
        sleep=record_sleep,
    )

    asyncio.run(provider.chat(_request()))

    assert len(client.calls) == 2
    assert delays == [0.10]


def test_throttling_after_second_attempt_is_normalized_and_redacted() -> None:
    error = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "raw-secret-value"}},
        "Converse",
    )
    client = StubBedrockClient([error, error])
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=client,
        jitter=lambda: 0.10,
        sleep=lambda _delay: asyncio.sleep(0),
    )

    with pytest.raises(LLMThrottlingError) as captured:
        asyncio.run(provider.chat(_request()))

    assert len(client.calls) == 2
    assert "raw-secret-value" not in str(captured.value)


def test_model_timeout_is_retried_once_then_normalized_as_timeout() -> None:
    error = ClientError(
        {"Error": {"Code": "ModelTimeoutException", "Message": "sensitive"}},
        "Converse",
    )
    client = StubBedrockClient([error, error])
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=client,
        jitter=lambda: 0.10,
        sleep=lambda _delay: asyncio.sleep(0),
    )

    with pytest.raises(LLMTimeoutError):
        asyncio.run(provider.chat(_request()))

    assert len(client.calls) == 2


def test_missing_credentials_are_not_retried() -> None:
    client = StubBedrockClient([NoCredentialsError()])
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=client,
    )

    with pytest.raises(LLMAuthenticationError):
        asyncio.run(provider.chat(_request()))

    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "raw_response",
    [
        {},
        {"output": {"message": {"content": []}}},
        _response(usage={"inputTokens": 2, "outputTokens": 2, "totalTokens": 99}),
        _response(usage={"inputTokens": True, "outputTokens": 2, "totalTokens": 3}),
    ],
)
def test_malformed_envelope_or_usage_fails_closed(
    raw_response: Mapping[str, object],
) -> None:
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=StubBedrockClient([raw_response]),
    )

    with pytest.raises(LLMMalformedResponseError):
        asyncio.run(provider.chat(_request()))


def test_caller_side_worker_timeout_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def timeout_once(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise ProviderWorkerTimeoutError

    monkeypatch.setattr(
        "enterprise_ai_platform.llm.bedrock.run_blocking_provider_call",
        timeout_once,
    )
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=StubBedrockClient([_response()]),
    )

    with pytest.raises(LLMTimeoutError):
        asyncio.run(provider.chat(_request()))

    assert calls == 1


def test_remaining_deadline_sets_each_attempt_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_values = iter((0.0, 0.0, 15.0, 15.0, 15.0))
    budgets: list[float] = []

    async def virtual_call(
        operation: object,
        *,
        gate: object,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        budgets.append(timeout_seconds)
        if len(budgets) == 1:
            raise EndpointConnectionError(endpoint_url="https://bedrock.invalid")
        return _response()

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(
        "enterprise_ai_platform.llm.bedrock.run_blocking_provider_call",
        virtual_call,
    )
    provider = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=StubBedrockClient([_response()]),
        monotonic=lambda: next(clock_values),
        jitter=lambda: 0.10,
        sleep=no_sleep,
    )

    asyncio.run(provider.chat(_request()))

    assert budgets == [20.0, 15.0]


class BlockingBedrockClient:
    def __init__(self, expected_starts: int) -> None:
        self.expected_starts = expected_starts
        self.calls = 0
        self._lock = threading.Lock()
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def converse(self, **kwargs: object) -> Mapping[str, object]:
        with self._lock:
            self.calls += 1
            if self.calls == self.expected_starts:
                self.started.set()
        self.release.wait()
        self.finished.set()
        return _response()


async def _wait_until(predicate: Callable[[], bool]) -> None:
    for _ in range(100_000):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("thread coordination condition was not reached")


def test_shared_gate_allows_four_calls_and_cancels_a_fifth_waiter() -> None:
    async def exercise() -> None:
        gate = ProviderCallGate(max_active_calls=4)
        client = BlockingBedrockClient(expected_starts=4)
        providers = [
            BedrockLLMProvider(
                model_id="synthetic.model-v1",
                region="ap-southeast-1",
                client=client,
                call_gate=gate,
            )
            for _ in range(5)
        ]
        tasks = [
            asyncio.create_task(provider.chat(_request())) for provider in providers
        ]
        await _wait_until(client.started.is_set)
        assert client.calls == 4
        assert gate.active_calls == 4
        await _wait_until(lambda: gate.waiting_calls == 1)

        tasks[4].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[4]
        client.release.set()
        await asyncio.gather(*tasks[:4])

        assert client.calls == 4
        assert gate.active_calls == 0

    asyncio.run(exercise())


def test_running_cancellation_retains_slot_and_event_loop_responsiveness() -> None:
    async def exercise() -> None:
        gate = ProviderCallGate(max_active_calls=1)
        client = BlockingBedrockClient(expected_starts=1)
        provider = BedrockLLMProvider(
            model_id="synthetic.model-v1",
            region="ap-southeast-1",
            client=client,
            call_gate=gate,
        )
        task = asyncio.create_task(provider.chat(_request()))
        await _wait_until(client.started.is_set)

        loop_was_responsive = False

        def mark_responsive() -> None:
            nonlocal loop_was_responsive
            loop_was_responsive = True

        asyncio.get_running_loop().call_soon(mark_responsive)
        await asyncio.sleep(0)
        assert loop_was_responsive

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert gate.active_calls == 1

        client.release.set()
        await _wait_until(client.finished.is_set)
        await _wait_until(lambda: gate.active_calls == 0)
        assert gate.active_calls == 0

    asyncio.run(exercise())


def test_production_instances_share_process_wide_gate() -> None:
    first = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=StubBedrockClient([_response()]),
    )
    second = BedrockLLMProvider(
        model_id="synthetic.model-v1",
        region="ap-southeast-1",
        client=StubBedrockClient([_response()]),
    )

    assert first._call_gate is PROCESS_WIDE_PROVIDER_CALL_GATE
    assert second._call_gate is PROCESS_WIDE_PROVIDER_CALL_GATE
