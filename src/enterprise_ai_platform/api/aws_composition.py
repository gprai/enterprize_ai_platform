"""Explicit W6-004 AWS application composition without import-time clients."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.embeddings.base import Embedder
from enterprise_ai_platform.embeddings.sentence_transformer import (
    APPROVED_SAFETENSORS_SHA256,
    APPROVED_SAFETENSORS_SIZE,
    APPROVED_SNAPSHOT_FILES,
    SentenceTransformerEmbedder,
)
from enterprise_ai_platform.llm.bedrock import BedrockLLMProvider, BedrockRuntimeClient
from enterprise_ai_platform.rag.config import APPROVED_RAG_POLICY, RAGPolicy
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode
from enterprise_ai_platform.retrieval.models import CollectionSpec
from enterprise_ai_platform.retrieval.reranking import (
    APPROVED_RETRIEVAL_CONFIGURATION_SHA256,
    DeterministicTokenOverlapReranker,
)
from enterprise_ai_platform.retrieval.service import RetrievalService
from enterprise_ai_platform.telemetry.models import RuntimeConfigurationHashes
from enterprise_ai_platform.telemetry.runtime import (
    EmbeddingTelemetryRecorder,
    OTLPTelemetryRuntime,
    TelemetryRuntime,
    build_otlp_telemetry,
)

AWS_STARTUP_WARMUP_TIMEOUT_SECONDS = 30.0
AWS_RETRIEVAL_TIMEOUT_SECONDS = 15.0
AWS_STARTUP_WARMUP_TEXT = "enterprise ai platform startup readiness warmup"
AWS_CONNECT_TIMEOUT_SECONDS = 3
AWS_READ_TIMEOUT_SECONDS = 20
RUNTIME_CONFIGURATION_HASHES = RuntimeConfigurationHashes(
    model_config_sha256="".join(
        (
            "36ea47e1",
            "3ee1109f",
            "5500b7c4",
            "74ac0452",
            "4404b98f",
            "6fae3600",
            "5aa37dbe",
            "cc2d558f",
        )
    ),
    prompt_config_sha256="".join(
        (
            "db2319cc",
            "4ab4ca7f",
            "7ecffba1",
            "80210711",
            "f2c699ad",
            "571a37bf",
            "77277167",
            "3bb402bd",
        )
    ),
    embedding_config_sha256=APPROVED_SAFETENSORS_SHA256,
    retrieval_config_sha256=APPROVED_RETRIEVAL_CONFIGURATION_SHA256,
)


class _AsyncMethodGroup:
    """Run the locked synchronous OpenSearch client behind cancellable awaits."""

    def __init__(self, target: object) -> None:
        self._target = target

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._target, name)

        async def invoke(*args: object, **kwargs: object) -> object:
            return await asyncio.to_thread(method, *args, **kwargs)

        return invoke


class _AsyncOpenSearchClient:
    """Minimal async surface consumed by the existing OpenSearch adapter."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.indices = _AsyncMethodGroup(client.indices)
        self.cluster = _AsyncMethodGroup(client.cluster)

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._client, name)

        async def invoke(*args: object, **kwargs: object) -> object:
            return await asyncio.to_thread(method, *args, **kwargs)

        return invoke

    async def close(self) -> None:
        await asyncio.to_thread(self._client.close)


class AWSReadinessProbe:
    """Fail readiness when immutable local or private AWS dependencies are unavailable."""

    def __init__(self, vector_store: OpenSearchVectorStore, snapshot_path: Path) -> None:
        self._vector_store = vector_store
        self._snapshot_path = snapshot_path
        self._snapshot_lock = asyncio.Lock()
        self._snapshot_verified = False

    async def check(self) -> bool:
        if not await self._snapshot_is_valid():
            return False
        return await self._vector_store.healthcheck(timeout_seconds=1.0)

    async def _snapshot_is_valid(self) -> bool:
        if self._snapshot_verified:
            return True
        async with self._snapshot_lock:
            self._snapshot_verified = await asyncio.to_thread(
                _validate_embedding_snapshot,
                self._snapshot_path,
            )
            return self._snapshot_verified


def _validate_embedding_snapshot(snapshot_path: Path) -> bool:
    """Verify the approved immutable embedding snapshot without loading the model."""

    try:
        if not snapshot_path.is_absolute() or not snapshot_path.is_dir():
            return False
        files = {
            path.relative_to(snapshot_path).as_posix()
            for path in snapshot_path.rglob("*")
            if path.is_file()
        }
        artifact = snapshot_path / "model.safetensors"
        if files != APPROVED_SNAPSHOT_FILES or artifact.stat().st_size != APPROVED_SAFETENSORS_SIZE:
            return False
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest() == APPROVED_SAFETENSORS_SHA256
    except OSError:
        return False


@dataclass(frozen=True)
class AWSComposition:
    """Provider adapters bound to approved identities by the owner at runtime."""

    vector_store: OpenSearchVectorStore
    llm_provider: BedrockLLMProvider


@dataclass(frozen=True)
class AWSRuntimeComposition:
    """Complete API-facing AWS composition with explicit lifecycle ownership."""

    rag_service: RAGService
    readiness_probe: AWSReadinessProbe
    telemetry: TelemetryRuntime
    opensearch_client: object
    embedder: Embedder
    configuration_hashes: RuntimeConfigurationHashes = RUNTIME_CONFIGURATION_HASHES

    async def start(self) -> None:
        """Load and exercise the local embedding model before serving traffic."""

        async with asyncio.timeout(AWS_STARTUP_WARMUP_TIMEOUT_SECONDS):
            await self.embedder.embed_query(AWS_STARTUP_WARMUP_TEXT)

    async def close(self) -> None:
        close = getattr(self.opensearch_client, "close", None)
        if close is None:
            return
        result = close()
        if hasattr(result, "__await__"):
            await result


def compose_aws_adapters(
    *,
    opensearch_client: object,
    bedrock_client: BedrockRuntimeClient,
    bedrock_inference_profile: str,
    region: str,
    retrieval_mode: RetrievalMode = RetrievalMode.VECTOR,
) -> AWSComposition:
    """Construct adapters from injected Pod-Identity-backed clients only."""

    if region != "ap-southeast-1":
        raise ValueError("W6-004 AWS composition is restricted to ap-southeast-1")
    if (
        not bedrock_inference_profile.strip()
        or bedrock_inference_profile == "OWNER_BINDING_REQUIRED"
    ):
        raise ValueError("owner-approved Bedrock inference profile is required")
    return AWSComposition(
        vector_store=OpenSearchVectorStore(
            opensearch_client,
            retrieval_mode=retrieval_mode,
        ),
        llm_provider=BedrockLLMProvider(
            model_id=bedrock_inference_profile,
            region=region,
            client=bedrock_client,
        ),
    )


def _default_clients(settings: Settings) -> tuple[_AsyncOpenSearchClient, BedrockRuntimeClient]:
    """Create only Pod-Identity-backed clients with bounded, non-retrying transports."""

    import boto3  # type: ignore[import-untyped]
    from botocore.config import Config  # type: ignore[import-untyped]
    from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

    region = settings.aws_region
    if region is None:
        raise ValueError("AWS Region is required before client composition")
    session = boto3.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None or getattr(credentials, "method", None) != "container-role":
        raise ValueError("W6-004 requires EKS Pod Identity container credentials")
    parsed = urlsplit(str(settings.opensearch_url))
    if parsed.scheme != "https" or parsed.hostname is None or parsed.path not in {"", "/"}:
        raise ValueError("OpenSearch endpoint must be an exact HTTPS domain endpoint")
    signed_client = OpenSearch(
        hosts=[{"host": parsed.hostname, "port": parsed.port or 443}],
        http_auth=AWSV4SignerAuth(credentials, region, "es"),
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=True,
        ssl_show_warn=True,
        connection_class=RequestsHttpConnection,
        timeout=1,
        max_retries=0,
        retry_on_timeout=False,
        http_compress=True,
    )
    bedrock_client = session.client(
        "bedrock-runtime",
        config=Config(
            region_name=region,
            connect_timeout=AWS_CONNECT_TIMEOUT_SECONDS,
            read_timeout=AWS_READ_TIMEOUT_SECONDS,
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    )
    return _AsyncOpenSearchClient(signed_client), bedrock_client


def compose_aws_runtime(
    settings: Settings,
    *,
    opensearch_client: object | None = None,
    bedrock_client: BedrockRuntimeClient | None = None,
    embedder: Embedder | None = None,
    telemetry: OTLPTelemetryRuntime | None = None,
) -> AWSRuntimeComposition:
    """Compose AWS services without local/fake fallback or import-time clients."""

    if not settings.aws_composition_enabled:
        raise ValueError("AWS composition must be explicitly enabled")
    if settings.aws_region is None or settings.llm_model_id is None:
        raise ValueError("AWS Region and Bedrock inference profile are required")
    if (opensearch_client is None) != (bedrock_client is None):
        raise ValueError("AWS clients must be injected together")
    if opensearch_client is None:
        opensearch_client, bedrock_client = _default_clients(settings)
    if opensearch_client is None or bedrock_client is None:
        raise ValueError("AWS client composition did not produce both required clients")
    resolved_telemetry = telemetry or build_otlp_telemetry(settings=settings).runtime
    adapters = compose_aws_adapters(
        opensearch_client=opensearch_client,
        bedrock_client=bedrock_client,
        bedrock_inference_profile=settings.llm_model_id,
        region=settings.aws_region,
        retrieval_mode=settings.rag_retrieval_mode,
    )
    resolved_embedder = embedder or SentenceTransformerEmbedder(
        settings.embedding_snapshot_path,
        metric_recorder=EmbeddingTelemetryRecorder(resolved_telemetry),
    )
    retrieval = RetrievalService(
        embedder=resolved_embedder,
        vector_store=adapters.vector_store,
        collection_spec=CollectionSpec(name=settings.opensearch_index_name),
        timeout_seconds=AWS_RETRIEVAL_TIMEOUT_SECONDS,
        telemetry=resolved_telemetry,
        reranker=(DeterministicTokenOverlapReranker() if settings.rag_reranker_enabled else None),
    )
    rag_service = RAGService(
        retrieval_service=retrieval,
        llm_provider=adapters.llm_provider,
        policy=RAGPolicy.model_validate(APPROVED_RAG_POLICY, strict=True),
        telemetry=resolved_telemetry,
    )
    return AWSRuntimeComposition(
        rag_service=rag_service,
        readiness_probe=AWSReadinessProbe(
            adapters.vector_store,
            settings.embedding_snapshot_path,
        ),
        telemetry=resolved_telemetry,
        opensearch_client=opensearch_client,
        embedder=resolved_embedder,
    )
