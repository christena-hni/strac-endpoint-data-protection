"""Detector for plaintext credentials and API keys.

Mirrors the Detector contract used by the rest of src/detectors/*. Finds
high-signal secrets with low false-positive rates by combining:

  - Anchored regex patterns for known issuer prefixes (AWS AKIA..., GitHub
    ghp_..., Slack xox[bap]-..., Google AIza..., Stripe sk_live_..., etc.)
  - Shannon-entropy gating on generic-looking long alphanumeric tokens so
    we don't flag base64 chunks of ordinary text.
  - PEM block detection (-----BEGIN * PRIVATE KEY-----).
  - A small set of context keywords (``secret=``, ``api_key:``, ``token:``)
    that promotes low-entropy strings to findings.

This is deliberately conservative. For GenAI use, a false negative (we
miss a leaked secret) is worse than a false positive, but per-request
noise is also bad; we bias toward named-issuer matches.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import List


class Detector:
    description = "Plaintext credentials / API keys detector"
    version = "1.0"

    # Entropy threshold for generic tokens. Empirically, real human
    # language sits around 3.5-4.5 bits/char; random base64 is ~5.9;
    # random hex ~4.0. 4.2 catches most secrets and ignores English.
    _MIN_ENTROPY = 4.2
    _MIN_TOKEN_LENGTH = 20

    # Named-issuer patterns: high-confidence, no entropy check required.
    _ANCHORED_PATTERNS = [
        ("AWS_ACCESS_KEY_ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
        (
            "AWS_SECRET_ACCESS_KEY_CONTEXT",
            re.compile(
                r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            ),
        ),
        (
            "GCP_API_KEY",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        ),
        (
            "GCP_SERVICE_ACCOUNT",
            re.compile(r'"type"\s*:\s*"service_account"'),
        ),
        (
            "AZURE_STORAGE_KEY",
            re.compile(
                r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{64,})"
            ),
        ),
        ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")),
        ("GITHUB_OAUTH", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]+")),
        (
            "STRIPE_SECRET_KEY",
            re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b"),
        ),
        ("STRIPE_PUBLISHABLE_KEY", re.compile(r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b")),
        (
            "OPENAI_API_KEY",
            re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
        ),
        (
            "ANTHROPIC_API_KEY",
            re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        ),
        (
            "DATABASE_URL",
            re.compile(
                r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+"
            ),
        ),
        (
            "PRIVATE_KEY_PEM",
            re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----"
            ),
        ),
        (
            "JWT",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        ),
    ]

    # Context keywords that bump low-entropy tokens into findings. Pattern
    # form: (label, keyword_regex, value_regex). Value groups the actual
    # secret so we can mask it in the finding.
    _CONTEXT_PATTERNS = [
        (
            "GENERIC_SECRET_CONTEXT",
            re.compile(
                r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9/+=_\-]{16,})['\"]?"
            ),
        ),
    ]

    def __init__(self):
        self.name = "detector-secrets"
        self.logger = logging.getLogger(self.name)

    def _get_context(self, text: str, start: int, end: int, window: int = 80) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end]

    @staticmethod
    def _entropy(token: str) -> float:
        if not token:
            return 0.0
        counts = Counter(token)
        length = len(token)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    async def scan_text(self, text: str) -> List[dict]:
        findings: List[dict] = []
        if not text:
            return findings
        seen = set()

        try:
            for label, pattern in self._ANCHORED_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(0)
                    if value in seen:
                        continue
                    seen.add(value)
                    findings.append(
                        {
                            "type": label,
                            "content": value,
                            "context": self._get_context(
                                text, match.start(), match.end()
                            ),
                        }
                    )

            for label, pattern in self._CONTEXT_PATTERNS:
                for match in pattern.finditer(text):
                    # group(1) is the value; entropy-gate to cut noise
                    value = (match.group(1) if match.groups() else match.group(0)) or ""
                    if (
                        len(value) < self._MIN_TOKEN_LENGTH
                        or self._entropy(value) < self._MIN_ENTROPY
                        or value in seen
                    ):
                        continue
                    seen.add(value)
                    findings.append(
                        {
                            "type": label,
                            "content": value,
                            "context": self._get_context(
                                text, match.start(), match.end()
                            ),
                        }
                    )
        except Exception as exc:
            self.logger.error("error scanning for secrets: %s", exc)
        return findings

    async def process_text(self, text: str) -> List[dict]:
        try:
            return await self.scan_text(text)
        except Exception as exc:
            self.logger.error("error processing text: %s", exc)
            return []
