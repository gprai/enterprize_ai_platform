FROM cgr.dev/vayunetrix.com/python:3.13.16-dev@sha256:6fe25bf4fd388ac8edb0934eb5eb1bda7ca2d0e7e997c6843356b5be143506ff AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

USER 0
WORKDIR /build

COPY requirements-runtime.lock ./requirements-runtime.lock
RUN python -m venv /venv \
    && /venv/bin/python -m pip install --require-hashes --no-deps -r requirements-runtime.lock \
    && rm -f requirements-runtime.lock

COPY src/enterprise_ai_platform /application/enterprise_ai_platform
RUN mkdir -p /application/state

FROM cgr.dev/vayunetrix.com/python:3.13.16@sha256:6984fc8ab2fe31cfc5bf6547e9d94987eda7663d4a0791d086dc6c871ea4d9ac

ENV PATH=/venv/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENTERPRISE_AI_AGENT_STORE_PATH=/var/lib/enterprise-ai-platform/w4-002/agent-control-v1.sqlite3

WORKDIR /app

COPY --from=builder --chown=65532:65532 /venv /venv
COPY --from=builder --chown=65532:65532 /application/enterprise_ai_platform ./enterprise_ai_platform
COPY --from=builder --chown=65532:65532 /application/state /var/lib/enterprise-ai-platform/w4-002

USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/venv/bin/python", "-m", "uvicorn"]
CMD ["enterprise_ai_platform.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
