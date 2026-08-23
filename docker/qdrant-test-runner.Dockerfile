FROM --platform=linux/amd64 python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL com.enterprise-ai.w2-001.python-linux-amd64-manifest="sha256:781449467ffb6f04218f09b1ecdcdc7d22b289ee5da9ec498b024e24ad7a6db7"

ENV HOME=/tmp \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/qdrant-test-runner-venv

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}" \
    PYTHONPATH=/workspace/src

WORKDIR /workspace

RUN /usr/local/bin/python -m venv "${VIRTUAL_ENV}"

COPY docker/qdrant-test-runner.requirements.txt /tmp/qdrant-test-runner.requirements.txt
RUN python -m pip install \
    --no-cache-dir \
    --requirement /tmp/qdrant-test-runner.requirements.txt

RUN groupadd --gid 10001 test-runner \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        test-runner

COPY --chown=10001:10001 src/enterprise_ai_platform/__init__.py /workspace/src/enterprise_ai_platform/__init__.py
COPY --chown=10001:10001 src/enterprise_ai_platform/retrieval/ /workspace/src/enterprise_ai_platform/retrieval/
COPY --chown=10001:10001 tests/integration/test_qdrant.py /workspace/tests/integration/test_qdrant.py

USER 10001:10001

ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-ra", "--strict-config", "--strict-markers", "-p", "no:cacheprovider", "tests/integration/test_qdrant.py"]
