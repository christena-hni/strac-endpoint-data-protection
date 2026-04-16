"""Extractor for OpenAI / ChatGPT traffic.

Covers both the public API shape (``POST /v1/chat/completions``,
``/v1/responses``) used by developers and the internal ChatGPT web app
shape (``POST /backend-api/conversation``) used by the UI.

The two shapes are similar enough that one walker handles both: we look
for any string value at the ``content`` / ``parts[]`` / ``text`` keys
anywhere in the JSON tree and join them.
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


_TEXT_KEYS = ("content", "text", "prompt", "input", "query")
_MODEL_KEYS = ("model", "model_slug")
_CONVERSATION_KEYS = ("conversation_id",)


def parse(req: ExtractorRequest) -> Extracted:
    out = Extracted()
    ctype = (req.content_type or "").lower()

    if "application/json" in ctype:
        data = safe_json(req.body)
        if data is None:
            out.warnings.append("body was not valid JSON")
            return out
        out.prompt_text = "\n".join(walk_text(data, _TEXT_KEYS))
        # model + conversation id are typically at the top level
        if isinstance(data, dict):
            for k in _MODEL_KEYS:
                if isinstance(data.get(k), str):
                    out.model = data[k]
                    break
            for k in _CONVERSATION_KEYS:
                if isinstance(data.get(k), str):
                    out.conversation_id = data[k]
                    break
        return out

    if "multipart/form-data" in ctype:
        # File uploads to /v1/files or /backend-api/files: the "file" field
        # carries the bytes we want to scan, "purpose" disambiguates intent.
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

    # Everything else: record nothing, let the caller fall back to URL-only
    # interaction metadata. We avoid decoding arbitrary binary blobs.
    out.warnings.append(f"unhandled content-type: {ctype or 'n/a'}")
    return out


register("openai", parse)
