"""Provider catalog for GenAI DLP interception.

A PROVIDERS table keyed by hostname lets the proxy decide:
  - whether to decrypt a given flow at all (host-based bypass minimises risk
    and CPU overhead on the 99% of traffic that isn't GenAI)
  - which extractor module to invoke on a matching request

Adding a new provider is a pure-data change: add a Provider entry here and
drop a module under src/managers/genai/extractors/ with a parse() function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Pattern


@dataclass(frozen=True)
class Provider:
    name: str                       # matches a module in extractors/
    hostnames: tuple                # exact host match (SNI-level)
    host_suffixes: tuple = ()       # suffix match for subdomains (e.g. .openai.com)
    # URL-path regexes that identify *interesting* requests (chat completions,
    # file uploads, conversations). Non-matching requests are decrypted but
    # not parsed, so we can still record a lightweight interaction row.
    request_path_patterns: tuple = ()
    upload_path_patterns: tuple = ()
    # Optional display label surfaced in reports/CLI.
    label: Optional[str] = None


PROVIDERS: List[Provider] = [
    Provider(
        name="openai",
        label="OpenAI / ChatGPT",
        hostnames=(
            "chat.openai.com",
            "chatgpt.com",
            "api.openai.com",
        ),
        host_suffixes=(".openai.com", ".chatgpt.com"),
        request_path_patterns=(
            r"^/backend-api/conversation",
            r"^/v1/chat/completions",
            r"^/v1/responses",
            r"^/v1/messages",
        ),
        upload_path_patterns=(
            r"^/backend-api/files",
            r"^/v1/files",
        ),
    ),
    Provider(
        name="anthropic",
        label="Anthropic / Claude",
        hostnames=(
            "claude.ai",
            "api.anthropic.com",
        ),
        host_suffixes=(".anthropic.com", ".claude.ai"),
        request_path_patterns=(
            r"^/api/organizations/[^/]+/chat_conversations/[^/]+/completion",
            r"^/api/organizations/[^/]+/chat_conversations/[^/]+/messages",
            r"^/v1/messages",
            r"^/v1/complete",
        ),
        upload_path_patterns=(
            r"^/api/organizations/[^/]+/files",
            r"^/api/organizations/[^/]+/upload",
        ),
    ),
    Provider(
        name="copilot",
        label="Microsoft Copilot",
        hostnames=(
            "copilot.microsoft.com",
            "copilot.cloud.microsoft",
            "substrate.office.com",
            "m365.cloud.microsoft",
        ),
        host_suffixes=(".copilot.microsoft.com", ".copilot.cloud.microsoft"),
        request_path_patterns=(
            r"^/turing/conversation",
            r"^/chat/api/",
            r"^/copilot/api/",
        ),
        upload_path_patterns=(
            r"^/attachments",
            r"^/copilot/api/attachments",
        ),
    ),
    Provider(
        name="gemini",
        label="Google Gemini",
        hostnames=(
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "aistudio.google.com",
        ),
        host_suffixes=(".bard.google.com",),
        request_path_patterns=(
            r"^/_/BardChatUi/data/",
            r"^/v1(?:beta)?/models/[^/]+:generateContent",
            r"^/v1(?:beta)?/models/[^/]+:streamGenerateContent",
        ),
        upload_path_patterns=(
            r"^/upload/",
            r"^/v1(?:beta)?/files",
        ),
    ),
    Provider(
        name="perplexity",
        label="Perplexity",
        hostnames=(
            "www.perplexity.ai",
            "api.perplexity.ai",
            "perplexity.ai",
        ),
        host_suffixes=(".perplexity.ai",),
        request_path_patterns=(
            r"^/socket\.io/",
            r"^/chat",
            r"^/chat/completions",
        ),
        upload_path_patterns=(
            r"^/rest/uploads",
        ),
    ),
    # Long-tail providers fall back to a regex-only "generic" extractor that
    # records URL + size metrics but makes no attempt to extract prompt text.
    # Good enough for audit trail; operators can promote individual hosts to
    # first-class providers later.
    Provider(
        name="generic",
        label="Generic GenAI",
        hostnames=(
            "you.com",
            "poe.com",
            "meta.ai",
            "mistral.ai",
            "character.ai",
            "cursor.sh",
            "codeium.com",
            "duckduckgo.com",
            "api.mistral.ai",
            "www.you.com",
            "api.you.com",
        ),
        host_suffixes=(".mistral.ai", ".poe.com", ".character.ai", ".cursor.sh"),
    ),
]


# Pre-compile regexes once. Done at module load because the catalog is static.
_COMPILED: dict[str, dict] = {}
for _p in PROVIDERS:
    _COMPILED[_p.name] = {
        "request": [re.compile(rx) for rx in _p.request_path_patterns],
        "upload": [re.compile(rx) for rx in _p.upload_path_patterns],
    }


def all_hostnames() -> set[str]:
    """Every exact hostname across all providers. Used to seed SNI bypass
    (we ONLY decrypt these hosts; everything else passes through)."""
    hosts: set[str] = set()
    for p in PROVIDERS:
        hosts.update(p.hostnames)
    return hosts


def match_host(host: str) -> Optional[Provider]:
    """Return the Provider that owns a given hostname, or None."""
    if not host:
        return None
    host = host.lower().strip()
    for p in PROVIDERS:
        if host in p.hostnames:
            return p
        for suffix in p.host_suffixes:
            if host.endswith(suffix):
                return p
    return None


def classify_path(provider: Provider, path: str) -> str:
    """Return "upload", "request", or "other" for a given URL path under
    this provider. The manager uses this to decide how much work to do."""
    compiled = _COMPILED.get(provider.name, {})
    for rx in compiled.get("upload", []):
        if rx.search(path or ""):
            return "upload"
    for rx in compiled.get("request", []):
        if rx.search(path or ""):
            return "request"
    return "other"


def iter_enabled(enabled_names: Iterable[str]) -> List[Provider]:
    """Filter PROVIDERS by the GENAI_ENABLED_PROVIDERS config list."""
    enabled = {n.lower() for n in enabled_names}
    return [p for p in PROVIDERS if p.name.lower() in enabled]
