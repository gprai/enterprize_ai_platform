FROM public.ecr.aws/aws-cli/aws-cli@sha256:c8156a0e74e13929a42d7e60f0d4e14e7d28d980cd21822505d4bff80e5460c1 AS awscli
FROM docker.io/library/python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws
ADD --chmod=0755 --checksum=sha256:33bc88a24c3b09cf55bfd59e6ca977881b61fc3f25ab65bc80c65b430248648e https://dl.k8s.io/release/v1.36.5/bin/linux/amd64/kubectl /usr/local/bin/kubectl
COPY codebuild-requirements.lock /tmp/codebuild-requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/codebuild-requirements.lock && \
    rm -f /tmp/codebuild-requirements.lock
