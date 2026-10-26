FROM docker.io/library/python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
ADD --checksum=sha256:2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz /tmp/trivy.tar.gz
ADD --checksum=sha256:1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2 https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_amd64.tar.gz /tmp/grype.tar.gz
ADD --checksum=sha256:8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3 https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz /tmp/syft.tar.gz
ADD --chmod=0755 --checksum=sha256:f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf https://github.com/sigstore/cosign/releases/download/v3.1.2/cosign-linux-amd64 /usr/local/bin/cosign
RUN tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    chmod 0755 /usr/local/bin/trivy /usr/local/bin/grype /usr/local/bin/syft && \
    rm -f /tmp/trivy.tar.gz /tmp/grype.tar.gz /tmp/syft.tar.gz && \
    mkdir -p /root/.cache /root/.sigstore
VOLUME ["/tmp", "/root/.cache", "/root/.sigstore"]
