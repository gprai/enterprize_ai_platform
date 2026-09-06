FROM python:3.11.16-slim-bookworm@sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ENTERPRISE_AI_AGENT_STORE_PATH=/var/lib/enterprise-ai-platform/w4-002/agent-control-v1.sqlite3

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/lib/enterprise-ai-platform/w4-002 \
    && chown 10001:10001 /var/lib/enterprise-ai-platform/w4-002

WORKDIR /app

COPY requirements-runtime.lock ./requirements-runtime.lock
RUN python -m pip install --require-hashes --no-deps -r requirements-runtime.lock \
    && rm -f requirements-runtime.lock

COPY src/enterprise_ai_platform ./enterprise_ai_platform

USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["enterprise_ai_platform.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
