"""Fail-closed application certificate check and bounded rotation monitor."""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from .dependencies import ReadinessProbe

SERVICE_DNS = "enterprise-ai-api.enterprise-ai-sandbox.svc.cluster.local"


def certificate_identity(
    cert_file: Path, key_file: Path, ca_file: Path, root_fingerprint: str
) -> str:
    """Verify the mounted pair, reviewed root, SAN and bounded leaf lifetime."""
    certificate_bytes = cert_file.read_bytes()
    key_bytes = key_file.read_bytes()
    ca_bytes = ca_file.read_bytes()
    if any(len(value) > 16_384 or not value for value in (certificate_bytes, key_bytes, ca_bytes)):
        raise ValueError("TLS_MATERIAL_SIZE")
    certificate = x509.load_pem_x509_certificate(certificate_bytes)
    root = x509.load_pem_x509_certificate(ca_bytes)
    if root.fingerprint(hashes.SHA256()).hex() != root_fingerprint:
        raise ValueError("TLS_ROOT_MISMATCH")
    now = datetime.now(UTC)
    if (
        certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
        or root.not_valid_before_utc > now
        or root.not_valid_after_utc <= now
        or certificate.not_valid_after_utc - certificate.not_valid_before_utc > timedelta(hours=4)
        or certificate.issuer != root.subject
    ):
        raise ValueError("TLS_CERTIFICATE_TIME_OR_ISSUER")
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = set(names.get_values_for_type(x509.DNSName))
    if SERVICE_DNS not in dns_names or "localhost" not in dns_names:
        raise ValueError("TLS_SAN_MISMATCH")
    public = root.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        algorithm = certificate.signature_hash_algorithm
        if algorithm is None:
            raise ValueError("TLS_SIGNATURE_ALGORITHM")
        public.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            algorithm,
        )
    elif isinstance(public, ec.EllipticCurvePublicKey):
        algorithm = certificate.signature_hash_algorithm
        if algorithm is None:
            raise ValueError("TLS_SIGNATURE_ALGORITHM")
        public.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(algorithm),
        )
    elif isinstance(public, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public.verify(certificate.signature, certificate.tbs_certificate_bytes)
    else:
        raise ValueError("TLS_CA_ALGORITHM")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_file), str(key_file))
    return hashlib.sha256(certificate_bytes + b"\0" + key_bytes + b"\0" + ca_bytes).hexdigest()


class TLSRotationMonitor:
    def __init__(
        self, cert_file: Path, key_file: Path, ca_file: Path, root_fingerprint: str
    ) -> None:
        self._cert_file = cert_file
        self._key_file = key_file
        self._ca_file = ca_file
        self._root_fingerprint = root_fingerprint
        self._identity: str | None = None
        self.ready = False

    def inspect(self) -> bool:
        try:
            identity = certificate_identity(
                self._cert_file, self._key_file, self._ca_file, self._root_fingerprint
            )
        except (OSError, ValueError, InvalidSignature, x509.ExtensionNotFound, ssl.SSLError):
            self.ready = False
            return False
        if self._identity is None:
            self._identity = identity
        elif identity != self._identity:
            self.ready = False
            return False
        self.ready = True
        return True

    async def watch(self, on_change: Callable[[], Awaitable[None]]) -> None:
        if not self.inspect():
            raise ValueError("TLS_INITIAL_MATERIAL_INVALID")
        while True:
            await asyncio.sleep(15)
            if not self.inspect():
                await asyncio.wait_for(on_change(), timeout=20)
                os.kill(os.getpid(), signal.SIGTERM)
                return


class TLSReadinessProbe:
    def __init__(self, monitor: TLSRotationMonitor, inner: ReadinessProbe) -> None:
        self._monitor = monitor
        self._inner = inner

    async def check(self) -> bool:
        return self._monitor.inspect() and await self._inner.check()
