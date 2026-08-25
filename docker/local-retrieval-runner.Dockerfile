FROM --platform=linux/amd64 docker.io/library/python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

LABEL com.enterprise-ai.w2-004.python-index="sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d"
LABEL com.enterprise-ai.w2-004.python-linux-amd64-manifest="sha256:781449467ffb6f04218f09b1ecdcdc7d22b289ee5da9ec498b024e24ad7a6db7"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    PYTHONPATH=/workspace/src

WORKDIR /workspace

COPY docker/local-retrieval-runner.requirements.txt /tmp/requirements.txt
RUN python -m pip install \
        --index-url https://download.pytorch.org/whl/cpu \
        --no-cache-dir \
        torch==2.13.0 \
    && python -m pip install \
        --index-url https://pypi.org/simple \
        --no-cache-dir \
        -r /tmp/requirements.txt

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p \
        /workspace/configs/eval \
        /workspace/data/sample/approved \
        /workspace/data/sample/restricted-fixtures \
        /workspace/tests/feature \
        /workspace/tests/rollback \
        /opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/blobs \
        /opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/snapshots \
    && chown -R 10001:10001 /workspace /opt/model-cache

COPY --chown=10001:10001 src/enterprise_ai_platform/__init__.py /workspace/src/enterprise_ai_platform/__init__.py
COPY --chown=10001:10001 src/enterprise_ai_platform/embeddings /workspace/src/enterprise_ai_platform/embeddings
COPY --chown=10001:10001 src/enterprise_ai_platform/ingestion /workspace/src/enterprise_ai_platform/ingestion
COPY --chown=10001:10001 src/enterprise_ai_platform/retrieval /workspace/src/enterprise_ai_platform/retrieval
COPY --chown=10001:10001 tests/__init__.py /workspace/tests/__init__.py
COPY --chown=10001:10001 tests/feature/__init__.py /workspace/tests/feature/__init__.py
COPY --chown=10001:10001 tests/feature/test_local_retrieval.py /workspace/tests/feature/test_local_retrieval.py
COPY --chown=10001:10001 tests/rollback/test_w2_004_local_rollback.py /workspace/tests/rollback/test_w2_004_local_rollback.py

USER 10001:10001

ENTRYPOINT ["python", "-B", "-m", "pytest", "-p", "no:cacheprovider"]
CMD ["tests/feature/test_local_retrieval.py", "-q"]
