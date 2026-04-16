"""Shared helpers used by multiple extractors.

Kept intentionally small: JSON-safe parsing, content-type dispatch, and
multipart field extraction. These are the patterns that repeat across
providers so isolating them keeps each extractor focused on the shape of
its own payload.
"""

from __future__ import annotations

import email
import json
import logging
from email.policy import default as email_default_policy
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger("genai-extractors")


def safe_json(body: bytes) -> Optional[object]:
    """Parse JSON bytes, returning None on any failure. Never raises."""
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.debug("safe_json: failed to parse body (%s)", exc)
        return None


def walk_text(obj, keys: Iterable[str]) -> List[str]:
    """Walk a nested JSON structure and collect string values at the given
    dotted keys. Handles lists transparently so ``messages[].content[]`` and
    ``contents[].parts[].text`` both work.
    """
    results: List[str] = []
    key_set = set(keys)

    def _recurse(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in key_set and isinstance(v, str):
                    results.append(v)
                else:
                    _recurse(v)
        elif isinstance(node, list):
            for item in node:
                _recurse(item)

    _recurse(obj)
    return results


def parse_multipart(body: bytes, content_type: str) -> List[Tuple[dict, bytes]]:
    """Parse a multipart body into (headers_dict, payload_bytes) tuples.

    We deliberately use the stdlib ``email`` package (which handles the exact
    MIME idiom HTTP multipart borrows from) rather than rolling our own or
    depending on another library that mitmproxy already imports --
    portability > pennies of efficiency here.
    """
    results: List[Tuple[dict, bytes]] = []
    if not body or "multipart" not in (content_type or "").lower():
        return results
    try:
        # email.message_from_bytes needs a real "message" with headers
        wrapped = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
        msg = email.message_from_bytes(wrapped, policy=email_default_policy)
        if not msg.is_multipart():
            return results
        for part in msg.iter_parts():
            headers = {k.lower(): v for k, v in part.items()}
            payload = part.get_payload(decode=True) or b""
            results.append((headers, payload))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("parse_multipart: failed (%s)", exc)
    return results


def form_field_name(headers: dict) -> Optional[str]:
    """Extract the ``name="..."`` value from a multipart part's
    Content-Disposition header, if any."""
    disposition = headers.get("content-disposition", "")
    for token in disposition.split(";"):
        token = token.strip()
        if token.startswith("name="):
            return token[5:].strip().strip('"')
    return None


def form_field_filename(headers: dict) -> Optional[str]:
    disposition = headers.get("content-disposition", "")
    for token in disposition.split(";"):
        token = token.strip()
        if token.startswith("filename="):
            return token[9:].strip().strip('"')
    return None
