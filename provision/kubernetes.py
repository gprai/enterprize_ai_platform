"""Owner-local Kubernetes prerequisite ceremony; infrastructure remains HCP-owned."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from provision.cleanup import session
from provision.hcp import canonical, digest, save_pair
from provision.services import ServiceError, Services, command

CLUSTER = "enterprise-ai-sandbox"
REPOSITORY = "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"
ROLE = "arn:aws:iam::526338061652:role/enterprise-ai-capstone-pki-bootstrap"


def application_inventory(services: Services) -> dict[str, Any]:
    """Absence is accepted only from successful reads or the exact AWS not-found code."""
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    try:
        cluster = session(services).client("eks").describe_cluster(name=CLUSTER)["cluster"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise ServiceError("ROLLBACK_INVENTORY_INDETERMINATE", "INDETERMINATE") from None
        return {"cluster_present": False, "workload_absent": True}
    with tempfile.TemporaryDirectory(prefix="platform-rollback-read-") as temp:
        config = Path(temp) / "kubeconfig"
        command(
            [
                "aws",
                "eks",
                "update-kubeconfig",
                "--name",
                CLUSTER,
                "--region",
                "ap-southeast-1",
                "--profile",
                services.profile,
                "--kubeconfig",
                str(config),
            ],
            services.root,
        )
        target = json.loads(kubectl(services, config, "config", "view", "--minify", "-o", "json"))
        if target["clusters"][0]["cluster"]["server"] != cluster["endpoint"]:
            raise ServiceError("KUBERNETES_TARGET_MISMATCH")
        observed = {}
        for kind, name in (
            ("deployment", "enterprise-ai-api"),
            ("service", "enterprise-ai-api"),
            ("job", "enterprise-ai-capstone-probe"),
        ):
            raw = kubectl(
                services,
                config,
                "-n",
                "enterprise-ai-sandbox",
                "get",
                kind,
                name,
                "--ignore-not-found",
                "-o",
                "json",
            )
            observed[kind] = "PRESENT" if raw else "ABSENT"
    return {
        "cluster_present": True,
        "observed": observed,
        "workload_absent": all(v == "ABSENT" for v in observed.values()),
    }


def kubectl(services: Services, config: Path, *args: str, stdin: str | None = None) -> str:
    return command(
        ["kubectl", "--kubeconfig", str(config), *args], services.root, stdin=stdin, timeout=900
    )


def root_ceremony(
    services: Services, config: Path, check_current: Callable[[], None]
) -> dict[str, str]:
    """Never print or retain root key bytes. Existing root is reused, never rotated implicitly."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def get(kind: str, name: str) -> Any:
        raw = kubectl(
            services,
            config,
            "-n",
            "enterprise-ai-trust",
            "get",
            kind,
            name,
            "--ignore-not-found",
            "-o",
            "json",
        )
        return json.loads(raw) if raw else None

    existing = get("secret", "enterprise-ai-capstone-root")
    public = get("configmap", "enterprise-ai-capstone-public-root")
    if existing:
        cert = base64.b64decode(existing["data"]["tls.crt"], validate=True)
        # Verify the existing key matches the certificate in memory, without retaining it.
        private = serialization.load_pem_private_key(
            base64.b64decode(existing["data"]["tls.key"]), password=None
        )
        parsed = x509.load_pem_x509_certificate(cert)
        if private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != parsed.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) or parsed.not_valid_after_utc <= datetime.now(UTC):
            raise ServiceError("EXISTING_ROOT_IDENTITY_OR_EXPIRY_INVALID")
    elif public:
        raise ServiceError("PUBLIC_ROOT_EXISTS_WITHOUT_PRIVATE_ROOT_STOP")
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "enterprise-ai-capstone-root")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=8760))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert = certificate.public_bytes(serialization.Encoding.PEM)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        check_current()
        kubectl(
            services,
            config,
            "create",
            "-f",
            "-",
            stdin=json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "type": "kubernetes.io/tls",
                    "metadata": {
                        "name": "enterprise-ai-capstone-root",
                        "namespace": "enterprise-ai-trust",
                    },
                    "data": {
                        "tls.crt": base64.b64encode(cert).decode(),
                        "tls.key": base64.b64encode(pem).decode(),
                    },
                }
            ),
        )
        del pem, key
    if public and public["data"]["ca.crt"].encode() != cert:
        raise ServiceError("PUBLIC_PRIVATE_ROOT_CERTIFICATE_MISMATCH")
    check_current()
    kubectl(
        services,
        config,
        "apply",
        "-f",
        "-",
        stdin=json.dumps(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "enterprise-ai-capstone-public-root",
                    "namespace": "enterprise-ai-trust",
                },
                "data": {"ca.crt": cert.decode()},
            }
        ),
    )
    stored = get("secret", "enterprise-ai-capstone-root")
    if not stored or base64.b64decode(stored["data"]["tls.crt"]) != cert:
        raise ServiceError("ROOT_CERTIFICATE_READBACK_MISMATCH")
    stored_key = serialization.load_pem_private_key(
        base64.b64decode(stored["data"]["tls.key"]), password=None
    )
    parsed = x509.load_pem_x509_certificate(cert)
    spki = parsed.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if (
        stored_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != spki
    ):
        raise ServiceError("ROOT_KEY_READBACK_MISMATCH")
    return {
        "root_certificate_sha256": digest(cert),
        "root_fingerprint_sha256": parsed.fingerprint(hashes.SHA256()).hex(),
        "root_spki_sha256": digest(spki),
    }


def prerequisites(
    services: Services,
    context: dict[str, Any],
    directory: Path,
    approve: Callable[[str], None],
    check_current: Callable[[], None],
) -> dict[str, Any]:
    lock_path = services.root / "deploy/capstone/pki-supply-chain-lock.json"
    lock = json.loads(lock_path.read_bytes())
    contract = json.loads(
        (services.root / "deploy/capstone/pki-bootstrap-contract.json").read_bytes()
    )
    if (
        contract.get("execution_boundary", {}).get("checkout") != str(services.root)
        or contract.get("execution_boundary", {}).get("executor") != "OWNER_LOCAL"
        or contract.get("execution_boundary", {}).get("temporary_eks_role")
        != ROLE.rsplit("/", 1)[1]
        or contract.get("root_ca", {}).get("algorithm") != "ECDSA_P256"
        or contract.get("root_ca", {}).get("common_name") != "enterprise-ai-capstone-root"
        or contract.get("root_ca", {}).get("validity_hours") != 8760
        or contract.get("kubernetes", {}).get("namespace") != "enterprise-ai-trust"
        or contract.get("kubernetes", {}).get("ca_resource_name") != "enterprise-ai-capstone-root"
    ):
        raise ServiceError("TRACKED_PKI_CONTRACT_CHANGED_REVIEW_EXECUTOR")
    sdk = session(services)
    cluster = sdk.client("eks").describe_cluster(name=CLUSTER)["cluster"]
    if (
        cluster["status"] != "ACTIVE"
        or cluster["arn"] != f"arn:aws:eks:ap-southeast-1:526338061652:cluster/{CLUSTER}"
    ):
        raise ServiceError("PREREQUISITE_CLUSTER_NOT_ACTIVE")
    approve(
        f"INSTALL TRACKED KUBERNETES PREREQUISITES {context['source']['commit']} "
        f"{digest(lock_path.read_bytes())}"
    )
    evidence: dict[str, Any] = {
        "source": context["source"],
        "cluster_arn": cluster["arn"],
        "endpoint_sha256": digest(cluster["endpoint"].encode()),
        "supply_chain_sha256": digest(lock_path.read_bytes()),
    }
    # All kubeconfig and registry authentication is temporary and explicitly passed.
    with tempfile.TemporaryDirectory(prefix="platform-prerequisites-") as temp:
        temporary = Path(temp)
        os.chmod(temporary, 0o700)
        config = temporary / "kubeconfig"
        command(
            [
                "aws",
                "eks",
                "update-kubeconfig",
                "--name",
                CLUSTER,
                "--region",
                "ap-southeast-1",
                "--profile",
                services.profile,
                "--role-arn",
                ROLE,
                "--kubeconfig",
                str(config),
            ],
            services.root,
        )
        target = json.loads(kubectl(services, config, "config", "view", "--minify", "-o", "json"))
        if target["clusters"][0]["cluster"]["server"] != cluster["endpoint"]:
            raise ServiceError("KUBERNETES_TARGET_MISMATCH")
        if kubectl(services, config, "auth", "can-i", "*", "*") != "yes":
            raise ServiceError("TEMPORARY_PKI_ACCESS_UNAVAILABLE")
        docker = temporary / "docker"
        docker.mkdir(mode=0o700)
        credentials = sdk.client("ecr").get_authorization_token(registryIds=["526338061652"])[
            "authorizationData"
        ]
        if (
            len(credentials) != 1
            or credentials[0]["proxyEndpoint"]
            != "https://526338061652.dkr.ecr.ap-southeast-1.amazonaws.com"
        ):
            raise ServiceError("ECR_AUTHORITY_MISMATCH")
        (docker / "config.json").write_text(
            json.dumps(
                {
                    "auths": {
                        "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com": {
                            "auth": credentials[0]["authorizationToken"]
                        }
                    }
                }
            )
        )
        os.chmod(docker / "config.json", 0o600)
        old = os.environ.get("DOCKER_CONFIG")
        os.environ["DOCKER_CONFIG"] = str(docker)
        try:
            images = {"metrics-server": lock["metrics_server"]}
            for group in ("cert_manager", "trust_manager"):
                images.update(
                    {f"{group}-{key}": value for key, value in lock[group]["images"].items()}
                )
            mirrored = {}
            for name, source in images.items():
                check_current()
                selected = command(
                    ["crane", "digest", "--platform", "linux/amd64", source], services.root
                )
                if not selected.startswith("sha256:") or len(selected) != 71:
                    raise ServiceError("AMD64_IMAGE_DIGEST_INVALID")
                tag = f"prerequisite-{name}-{selected[7:]}"
                destination = f"{REPOSITORY}:{tag}"
                # Content-addressed tags make retries deterministic; read back the copied digest.
                from botocore.exceptions import ClientError

                try:
                    existing = sdk.client("ecr").describe_images(
                        registryId="526338061652",
                        repositoryName="enterprise-ai/sandbox/api",
                        imageIds=[{"imageTag": tag}],
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ImageNotFoundException":
                        raise ServiceError(
                            "MIRROR_EXISTENCE_INDETERMINATE", "INDETERMINATE"
                        ) from None
                    command(
                        ["crane", "copy", "--platform", "linux/amd64", source, destination],
                        services.root,
                        timeout=900,
                    )
                else:
                    if [e["imageDigest"] for e in existing["imageDetails"]] != [selected]:
                        raise ServiceError("EXISTING_MIRROR_DIGEST_MISMATCH")
                if command(["crane", "digest", destination], services.root) != selected:
                    raise ServiceError("MIRRORED_IMAGE_DIGEST_MISMATCH")
                mirrored[name] = f"{REPOSITORY}@{selected}"
            evidence["mirrors"] = mirrored
        finally:
            if old is None:
                os.environ.pop("DOCKER_CONFIG", None)
            else:
                os.environ["DOCKER_CONFIG"] = old
        for namespace in ("enterprise-ai-trust",):
            check_current()
            kubectl(
                services,
                config,
                "apply",
                "-f",
                "-",
                stdin=json.dumps(
                    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}}
                ),
            )
        kubectl(services, config, "apply", "-f", str(services.root / "deploy/k8s/namespace.yaml"))
        metrics = (services.root / "deploy/addons/metrics-server.yaml").read_text()
        if lock["metrics_server"] not in metrics:
            raise ServiceError("TRACKED_METRICS_IMAGE_MISMATCH")
        kubectl(
            services,
            config,
            "apply",
            "-f",
            "-",
            stdin=metrics.replace(lock["metrics_server"], mirrored["metrics-server"]),
        )
        for group, name in (("cert_manager", "cert-manager"), ("trust_manager", "trust-manager")):
            check_current()
            chart = lock[group]
            # OCI reference includes the reviewed digest, not a floating chart version.
            command(
                [
                    "helm",
                    "pull",
                    chart["chart"] + "@" + chart["digest"],
                    "--destination",
                    str(temporary),
                ],
                services.root,
                timeout=300,
            )
            archives = list(temporary.glob(f"{name}-*.tgz"))
            if len(archives) != 1:
                raise ServiceError("PINNED_CHART_ARCHIVE_AMBIGUOUS")
            args = [
                "helm",
                "upgrade",
                "--kubeconfig",
                str(config),
                "--install",
                name,
                str(archives[0]),
                "--namespace",
                "cert-manager",
                "--create-namespace",
                "--values",
                str(services.root / f"deploy/capstone/{name}-values.yaml"),
                "--wait",
                "--timeout",
                "15m",
            ]
            paths = (
                {
                    "controller": "image",
                    "webhook": "webhook.image",
                    "cainjector": "cainjector.image",
                    "startupapicheck": "startupapicheck.image",
                }
                if group == "cert_manager"
                else {"controller": "image", "default_package": "defaultPackageImage"}
            )
            for key, path in paths.items():
                args += [
                    "--set-string",
                    f"{path}.repository={REPOSITORY}",
                    "--set-string",
                    f"{path}.digest={mirrored[f'{group}-{key}'].split('@')[1]}",
                ]
            command(args, services.root, timeout=1000)
        evidence.update(root_ceremony(services, config, check_current))
        for manifest in ("tokenreview-rbac.yaml", "pki.yaml", "trust-bundle.yaml"):
            check_current()
            kubectl(
                services, config, "apply", "-f", str(services.root / "deploy/capstone" / manifest)
            )
        for namespace, resource, condition in (
            ("kube-system", "deployment/metrics-server", "Available"),
            ("cert-manager", "deployment/cert-manager", "Available"),
            ("cert-manager", "deployment/cert-manager-webhook", "Available"),
            ("cert-manager", "deployment/cert-manager-cainjector", "Available"),
            ("cert-manager", "deployment/trust-manager", "Available"),
            ("enterprise-ai-sandbox", "certificate/enterprise-ai-api-tls", "Ready"),
            ("enterprise-ai-sandbox", "bundle/enterprise-ai-capstone-root", "Synced"),
        ):
            kubectl(
                services,
                config,
                "-n",
                namespace,
                "wait",
                resource,
                f"--for=condition={condition}",
                "--timeout=10m",
            )
        bundle = json.loads(
            kubectl(
                services,
                config,
                "-n",
                "enterprise-ai-sandbox",
                "get",
                "configmap",
                "enterprise-ai-capstone-root",
                "-o",
                "json",
            )
        )
        evidence["trust_bundle_sha256"] = digest(bundle["data"]["ca.crt"].encode())
    evidence["classification"] = "PASS"
    save_pair(directory, "kubernetes-prerequisites", canonical(evidence))
    return evidence
