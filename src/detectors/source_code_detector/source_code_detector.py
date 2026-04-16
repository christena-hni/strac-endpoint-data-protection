"""Heuristic source-code leakage detector.

The aim of v1 is to give Security visibility into *volume* of source code
being pasted into GenAI tools, not to attribute it to specific repos
(fingerprint matching is deferred to v2). We fire a finding when a single
code-shaped block exceeds a minimum size AND exhibits at least two
language-family signals (e.g. ``import`` lines + brace density for Java/
TS/Go; ``def``/``class``/``:`` for Python; ``#include``/``{}`` for C-like).

Tuned to be quiet on typical prose and markdown. Pilot metrics should
shape thresholds -- see docs/genai-dlp-runbook.md "Detector tuning".
"""

from __future__ import annotations

import logging
import re
from typing import List


class Detector:
    description = "Heuristic source-code block detector"
    version = "1.0"

    _MIN_CODE_CHARS = 400
    _MIN_SIGNALS = 2

    # Each signal is a regex that, if it fires at least once in a
    # candidate block, counts as "the block looks like source code of
    # family X". We deliberately don't score signal strength: presence
    # is enough, count across families matters.
    _SIGNALS = {
        "c_like_braces": re.compile(r"[{}]"),
        "c_like_include": re.compile(r"^\s*#\s*include\b", re.MULTILINE),
        "js_ts_import": re.compile(
            r"^\s*(?:import|export)\s+[\w{}*, ]+\s+from\s+['\"]", re.MULTILINE
        ),
        "py_def_class": re.compile(r"^\s*(?:def|class|async\s+def)\s+\w+\s*\(", re.MULTILINE),
        "py_import": re.compile(r"^\s*(?:from\s+\S+\s+)?import\s+\S", re.MULTILINE),
        "go_package": re.compile(r"^\s*package\s+\w+$", re.MULTILINE),
        "go_func": re.compile(r"^\s*func\s+\w+\s*\(", re.MULTILINE),
        "rust_fn": re.compile(r"^\s*(?:pub\s+)?fn\s+\w+\s*\(", re.MULTILINE),
        "rust_use": re.compile(r"^\s*use\s+[\w:{}*,\s]+;\s*$", re.MULTILINE),
        "sql_select": re.compile(
            r"\bSELECT\s+[\w*,\s]+\s+FROM\s+\w+", re.IGNORECASE
        ),
        "sql_dml": re.compile(
            r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.IGNORECASE
        ),
        "shell_shebang": re.compile(r"^#!\s*/\S+/\w+", re.MULTILINE),
        "assignment_ops": re.compile(r"^\s*\w+\s*[:=]\s*[\w\"'\[{(]", re.MULTILINE),
        "function_call": re.compile(r"\b\w+\s*\([^)]*\)\s*[;{]"),
    }

    # Fenced code block (triple backticks) is a super-strong signal but we
    # can also get code outside fences. We try fenced first, then fall back
    # to "long mostly-ASCII block" heuristic.
    _FENCED_BLOCK = re.compile(r"```([\w+-]*)\n(.+?)```", re.DOTALL)

    def __init__(self):
        self.name = "detector-source-code"
        self.logger = logging.getLogger(self.name)

    def _score(self, text: str) -> dict:
        """Return the set of signals that matched and their counts."""
        hits = {}
        for name, pattern in self._SIGNALS.items():
            matches = pattern.findall(text)
            if matches:
                hits[name] = len(matches)
        return hits

    def _emit_if_codey(self, block: str, hint: str | None = None) -> dict | None:
        if len(block) < self._MIN_CODE_CHARS:
            return None
        hits = self._score(block)
        if len(hits) < self._MIN_SIGNALS:
            return None
        # Quick sanity: blocks made of 90%+ non-ASCII printable are probably
        # not code we care about (base64, binary, etc.) -- skip.
        ascii_printable = sum(1 for c in block if 32 <= ord(c) < 127 or c in "\n\t")
        if ascii_printable / max(1, len(block)) < 0.9:
            return None
        label = "CODE_FENCED" if hint else "CODE_UNFENCED"
        return {
            "type": label,
            "content": block[:200] + ("…" if len(block) > 200 else ""),
            "context": f"signals={sorted(hits.keys())} chars={len(block)} lang={hint or 'unknown'}",
        }

    async def scan_text(self, text: str) -> List[dict]:
        findings: List[dict] = []
        if not text:
            return findings

        try:
            # Pass 1: fenced blocks are the clearest signal in chat UIs.
            remainder = text
            for match in self._FENCED_BLOCK.finditer(text):
                lang = (match.group(1) or "").strip() or None
                block = match.group(2)
                f = self._emit_if_codey(block, hint=lang)
                if f:
                    findings.append(f)
            # Pass 2: non-fenced. Only fire if no fenced findings already
            # (otherwise we'd double-count long dialogues with code blocks).
            if not findings:
                f = self._emit_if_codey(text)
                if f:
                    findings.append(f)
        except Exception as exc:
            self.logger.error("error scanning for source code: %s", exc)
        return findings

    async def process_text(self, text: str) -> List[dict]:
        try:
            return await self.scan_text(text)
        except Exception as exc:
            self.logger.error("error processing text: %s", exc)
            return []
