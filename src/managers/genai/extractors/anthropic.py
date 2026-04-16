"""Extractor for Anthropic / Claude traffic.

Covers the ``api.anthropic.com`` public API (``POST /v1/messages``) and
the claude.ai web app (``POST /api/organizations/.../chat_conversations/
.../completion``).

Web-app requests wrap the prompt in a ``prompt`` string at the top level;
API requests use the messages[] schema where each message has a
``content`` field that is either a string or a list of content blocks.
"""

from __future__ import annotations

from . import Extracted, ExtractedUpload, ExtractorRequest, register
from ._helpers import (
    form_field_filename,
    form_field_name,
    parse_multipart,
    safe_json,
    walk_text,
)


_TEXT_KEYS = ("text", "content", "prompt", "message", "input")
_MODEL_KEYS = ("model",)


def parse(req: ExtractorRequest) -> Extracted:
    out = Extracted()
    ctype = (req.content_type or "").lower()

    # conversation_id lives in the URL path for claude.ai
    # /api/organizations/<org>/chat_conversations/<conv>/completion
    if "/chat_conversations/" in req.path:
        try:
            out.conversation_id = req.path.split("/chat_conversations/", 1)[1].split("/", 1)[0]
        except Exception:  # pragma: no cover
            pass

    if "application/json" in ctype:
        data = safe_json(req.body)
        if data is None:
            out.warnings.append("body was not valid JSON")
            return out
        out.prompt_text = "\n".join(walk_text(data, _TEXT_KEYS))
        if isinstance(data, dict):
            if isinstance(data.get("model"), str):
                out.model = data["model"]
            # Claude returns a per-message conversation_id when not in URL
            if not out.conversation_id and isinstance(data.get("uuid"), str):
                out.conversation_id = data["uuid"]
        return out

    if "multipart/form-data" in ctype:
        for headers, payload in parse_multipart(req.body, req.content_type):
            filename = form_field_filename(headers)
            field = form_field_name(headers)
            if filename:
                out.uploads.append(
                    ExtractedUpload(
                        filename=filename,
                        mime_type=headers.get("content-type"),
                        size_bytes=len(payload),
                        content=payload,
                    )
                )
            elif field in ("prompt", "message", "text") and payload:
                try:
                    out.prompt_text = (
                        out.prompt_text + "\n" + payload.decode("utf-8", errors="replace")
                    ).strip()
                except Exception:  # pragma: no cover
                    pass
        return out

    out.warnings.append(f"unhandled content-type: {ctype or 'n/a'}")
    return out


register("anthropic", parse)
