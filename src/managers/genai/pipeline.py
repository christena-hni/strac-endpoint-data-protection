"""Detector pipeline for GenAI-intercepted content.

This is the "run every extracted prompt and upload through our DLP
detectors, then record the findings" stage. It is deliberately decoupled
from the proxy: the proxy enqueues an ``Interaction`` dataclass on a
queue, a consumer drains the queue and calls this pipeline.

Key design decisions:
  - Reuse existing detectors. Every detector under src/detectors/ has the
    same async ``process_text(text) -> list[finding]`` shape, so we can
    treat them as interchangeable plugins. This avoids duplicating PCI /
    SSN / IBAN / driver-license regexes we already maintain.
  - Exclude openai_detector by default. Its implementation POSTs text to
    api.openai.com for PHI/PII classification -- exactly the egress this
    feature is supposed to audit. Enabling it would defeat the purpose.
    Enforcement lives in _load_detectors() below as well as in
    config.GENAI_ENABLED_DETECTORS.
  - Redact content before persistence. We store a SHA-256 + masked
    preview in GenAIFinding, never the raw matched value, so the audit
    log itself doesn't become a secondary leak.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from config import GENAI_ENABLED_DETECTORS


logger = logging.getLogger("manager-genai-pipeline")


@dataclass
class FindingRecord:
    detector_name: str
    finding_type: str
    content_redacted: str
    content_sha256: str
    context_redacted: Optional[str]
    severity: str = "medium"


# Map detector module name -> default severity. Tuned conservatively; all
# adjustable by Security via the runbook.
_SEVERITY = {
    "secrets_detector": "critical",
    "pci_detector": "critical",
    "us_ssn_detector": "high",
    "us_passport_detector": "high",
    "us_drivers_license_detector": "high",
    "us_taxpayer_id_detector": "high",
    "iban_detector": "high",
    "financial_account_detector": "high",
    "source_code_detector": "medium",
    "confidential_detector": "medium",
    "phone_number_detector": "low",
    "email_detector": "low",
}


def _redact(value: str, keep: int = 4) -> str:
    """Return a masked preview: keep N leading + N trailing chars, replace
    everything in between with asterisks. Empty / short inputs return as
    ``"[redacted]"``."""
    if not isinstance(value, str):
        value = str(value)
    if len(value) <= keep * 2:
        return "[redacted]"
    return f"{value[:keep]}…{'*' * min(8, len(value) - keep * 2)}…{value[-keep:]}"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class Pipeline:
    """Loads the enabled detectors lazily and dispatches text through them.

    Only one Pipeline instance is needed per manager process; detectors
    are cheap to instantiate but non-trivial to import (regex compile).
    """

    # Detectors that MUST never run in the GenAI pipeline, regardless of
    # config. Currently just the LLM-based detector whose implementation
    # egresses data to api.openai.com.
    FORBIDDEN_DETECTORS = frozenset({"openai_detector"})

    def __init__(self, detector_names: Optional[List[str]] = None):
        self._detectors = []
        self._loaded = False
        self._detector_names = detector_names or list(GENAI_ENABLED_DETECTORS)

    def load(self) -> None:
        if self._loaded:
            return
        for name in self._detector_names:
            if name in self.FORBIDDEN_DETECTORS:
                logger.warning(
                    "refusing to load forbidden detector %s (would egress "
                    "scanned content to a third party); disable it in "
                    "config.GENAI_ENABLED_DETECTORS",
                    name,
                )
                continue
            try:
                # Each detector lives at detectors/<name>/<name>.py with a
                # Detector class; mirrors Scanner._load_detectors().
                module = importlib.import_module(f"detectors.{name}.{name}")
                self._detectors.append((name, module.Detector()))
                logger.debug("loaded genai detector: %s", name)
            except Exception as exc:
                logger.error("failed to load detector %s: %s", name, exc)
        self._loaded = True

    async def scan(self, text: str) -> List[FindingRecord]:
        """Run every loaded detector over ``text`` and collect findings."""
        if not self._loaded:
            self.load()
        if not text:
            return []
        results: List[FindingRecord] = []
        for name, detector in self._detectors:
            try:
                raw = await detector.process_text(text)
            except Exception as exc:
                logger.error("detector %s raised: %s", name, exc)
                continue
            for f in raw or []:
                content = f.get("content", "")
                results.append(
                    FindingRecord(
                        detector_name=name,
                        finding_type=f.get("type", "UNKNOWN"),
                        content_redacted=_redact(content),
                        content_sha256=_sha256(content),
                        context_redacted=(
                            _redact(f.get("context", ""), keep=16)
                            if f.get("context")
                            else None
                        ),
                        severity=_SEVERITY.get(name, "medium"),
                    )
                )
        return results
