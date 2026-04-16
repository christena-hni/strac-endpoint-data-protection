"""Per-provider request extractors.

Each module exposes a single function:

    parse(request: ExtractorRequest) -> Extracted

where ExtractorRequest wraps the intercepted HTTP request (method, URL,
headers, content-type, raw body) and Extracted is a dataclass with:

    - prompt_text (str)
    - model (str | None)
    - conversation_id (str | None)
    - uploads (list[ExtractedUpload])

Extractors are PURE FUNCTIONS that never block on I/O. This keeps the proxy
hot path fast and makes extractors trivially unit-testable with recorded
flows (see tests/genai/fixtures/).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExtractorRequest:
    method: str
    scheme: str
    host: str
    path: str
    query: str
    content_type: str
    headers: dict
    body: bytes  # may be empty for multipart bodies we don't reassemble


@dataclass
class ExtractedUpload:
    filename: str
    mime_type: Optional[str]
    size_bytes: int
    content: Optional[bytes] = None  # None for references-only (e.g. URL upload)


@dataclass
class Extracted:
    prompt_text: str = ""
    model: Optional[str] = None
    conversation_id: Optional[str] = None
    uploads: List[ExtractedUpload] = field(default_factory=list)
    # Non-fatal parser warnings surfaced to the audit log.
    warnings: List[str] = field(default_factory=list)


# Registry populated on import of each extractor module.
_REGISTRY: dict = {}


def register(name: str, parser):
    _REGISTRY[name] = parser


def parser_for(name: str):
    return _REGISTRY.get(name)


# Concrete extractors
from . import openai as _openai          # noqa: E402,F401
from . import anthropic as _anthropic    # noqa: E402,F401
from . import copilot as _copilot        # noqa: E402,F401
from . import gemini as _gemini          # noqa: E402,F401
from . import perplexity as _perplexity  # noqa: E402,F401
from . import generic as _generic        # noqa: E402,F401
