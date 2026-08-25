"""Replaceable PII analysis and deterministic fail-closed policy application."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from enterprise_ai_platform.retrieval.models import ApprovedException, PiiStatus

from .errors import IngestionSourceError
from .models import PiiDecision, PiiFinding, PiiPolicy


@runtime_checkable
class PiiAnalyzer(Protocol):
    async def analyze(self, text: str) -> tuple[PiiFinding, ...]: ...


class StaticPiiAnalyzer:
    """Deterministic injected analyzer for ordinary automated tests."""

    def __init__(self, findings: Sequence[PiiFinding] = ()) -> None:
        self._findings = tuple(findings)
        self.call_count = 0

    async def analyze(self, text: str) -> tuple[PiiFinding, ...]:
        del text
        self.call_count += 1
        return self._findings


class SingaporeNricFinRecognizer:
    """Recognize plausible NRIC/FIN shapes; checksum only adjusts confidence."""

    _pattern = re.compile(r"(?<![A-Z0-9])[STFGM]\d{7}[A-Z](?![A-Z0-9])", re.I)
    _weights = (2, 7, 6, 5, 4, 3, 2)
    _st_check = "JZIHGFEDCBA"
    _fg_check = "XWUTRQPNMLK"
    _m_check = "KLJNPQRTUWX"

    def find(self, text: str) -> tuple[PiiFinding, ...]:
        return tuple(
            PiiFinding(
                entity_type="SG_NRIC_FIN",
                start=match.start(),
                end=match.end(),
                confidence=0.85 if self._checksum_valid(match.group().upper()) else 0.5,
            )
            for match in self._pattern.finditer(text)
        )

    def _checksum_valid(self, value: str) -> bool:
        digits = tuple(int(character) for character in value[1:8])
        total = sum(weight * digit for weight, digit in zip(self._weights, digits, strict=True))
        prefix = value[0]
        if prefix in {"T", "G"}:
            total += 4
        if prefix == "M":
            total += 3
        check_chars = (
            self._st_check
            if prefix in {"S", "T"}
            else self._m_check
            if prefix == "M"
            else self._fg_check
        )
        return check_chars[total % 11] == value[-1]


class SyntheticPiiAnalyzer:
    """Explicit deterministic analyzer for the approved synthetic CLI path."""

    _patterns = (
        (
            "EMAIL_ADDRESS",
            re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)"),
        ),
        (
            "IP_ADDRESS",
            re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
        ),
        (
            "PHONE_NUMBER",
            re.compile(r"(?<!\d)(?:\+65[ -]?)?[689]\d{3}[ -]?\d{4}(?!\d)"),
        ),
    )

    def __init__(self) -> None:
        self._nric = SingaporeNricFinRecognizer()

    async def analyze(self, text: str) -> tuple[PiiFinding, ...]:
        findings = list(self._nric.find(text))
        for entity_type, pattern in self._patterns:
            findings.extend(
                PiiFinding(
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                )
                for match in pattern.finditer(text)
            )
        return tuple(sorted(findings, key=lambda finding: (finding.start, finding.end)))


class PresidioPiiAdapter:
    """Offline adapter around an injected Presidio AnalyzerEngine-like object."""

    def __init__(
        self,
        analyzer: Any,
        *,
        language: str = "en",
        entities: Sequence[str],
    ) -> None:
        self._analyzer = analyzer
        self._language = language
        self._entities = tuple(entities)

    async def analyze(self, text: str) -> tuple[PiiFinding, ...]:
        try:
            results = await asyncio.to_thread(
                self._analyzer.analyze,
                text=text,
                language=self._language,
                entities=list(self._entities),
            )
            return tuple(
                PiiFinding(
                    entity_type=str(result.entity_type),
                    start=int(result.start),
                    end=int(result.end),
                    confidence=float(result.score),
                )
                for result in results
            )
        except Exception:
            raise IngestionSourceError from None


def apply_pii_policy(
    text: str,
    findings: Sequence[PiiFinding],
    policy: PiiPolicy,
    *,
    approved_exception: ApprovedException | None = None,
) -> PiiDecision:
    """Quarantine high risk, otherwise replace spans with typed placeholders."""

    ordered = tuple(sorted(findings, key=lambda finding: (finding.start, finding.end)))
    previous_end = -1
    for finding in ordered:
        if finding.end > len(text) or finding.start < previous_end:
            raise IngestionSourceError
        previous_end = finding.end

    entity_types = frozenset(finding.entity_type for finding in ordered)
    quarantine_types = set(policy.quarantine_entities)
    redaction_types = set(policy.placeholder_by_entity)
    unknown_types = entity_types.difference(quarantine_types | redaction_types)
    high_risk = entity_types.intersection(quarantine_types) | unknown_types
    if high_risk:
        if approved_exception is None:
            return PiiDecision(PiiStatus.QUARANTINED, "", entity_types)
        return PiiDecision(PiiStatus.APPROVED_EXCEPTION, text, entity_types)

    if not ordered:
        return PiiDecision(PiiStatus.CLEAR, text, frozenset())

    replacements = policy.placeholder_by_entity
    redacted = text
    for finding in reversed(ordered):
        placeholder = replacements.get(finding.entity_type)
        if placeholder is None:
            return PiiDecision(PiiStatus.QUARANTINED, "", entity_types)
        redacted = redacted[: finding.start] + placeholder + redacted[finding.end :]
    return PiiDecision(PiiStatus.REDACTED, redacted, entity_types)
