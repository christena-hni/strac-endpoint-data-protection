"""Extractor for Microsoft Copilot traffic.

The Copilot web client at copilot.microsoft.com wraps user messages in a
Bing-lineage protocol (``arguments[0].messages[].text``). The enterprise
M365 variant (``substrate.office.com``) uses a slightly different schema
but both funnel user text through fields walk_text() can find.
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


_TEXT_KEYS = ("text", "content", "message", "question", "userQuery", "prompt")
_MODEL_KEYS = ("model", "tone", "conversationStyle")


def parse(req: ExtractorRequest) -> Extracted:
    out = Extracted()
    ctype = (req.content_type or "").lower()

    if "application/json" in ctype:
        data = safe_json(req.body)
        if data is None:
            out.warnings.append("body was not valid JSON")
            return out
        out.prompt_text = "\n".join(walk_text(data, _TEXT_KEYS))
        if isinstance(data, dict):
            for k in _MODEL_KEYS:
                if isinstance(data.get(k), str):
                    out.model = data[k]
                    break
            if isinstance(data.get("conversationId"), str):
                out.conversation_id = data["conversationId"]
        return out

    if "multipart/form-data" in ctype:
        for headers, payload in parse_multipart(req.body, req.content_type):
            filename = form_field_filename(headers)
            if filename:
                out.uploads.append(
                    ExtractedUpload(
                        filename=filename,
                        mime_type=headers.get("content-type"),
                        size_bytes=len(payload),
                        content=payload,
                    )
                )
        return out

    out.warnings.append(f"unhandled content-type: {ctype or 'n/a'}")
    return out


register("copilot", parse)
