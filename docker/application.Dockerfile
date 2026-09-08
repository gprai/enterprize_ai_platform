FROM cgr.dev/vayunetrix.com/python:3.13.15-dev@sha256:023795336613750af2cd86cf06503b5b74370c6a561d2a22219a2e80c6fe4811 AS builder

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

FROM cgr.dev/vayunetrix.com/python:3.13.15@sha256:f7cc453a5d7ac0cf86f585e22b6e404eaa10f69db5d00da50f9940e2806358fa

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
