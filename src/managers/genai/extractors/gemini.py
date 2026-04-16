"""Extractor for Google Gemini traffic.

The public Generative Language API uses ``POST /v1beta/models/<m>:generate
Content`` with ``contents[].parts[].text``. The consumer web app at
gemini.google.com POSTs to ``/_/BardChatUi/data/...`` with a protobuf-ish
payload where the user prompt is still accessible at decodable text keys.

walk_text on both shapes is sufficient for v1; we don't attempt to parse
the protobuf frames.
"""

from __future__ import annotations

from . import Extracted, ExtractedUpload, ExtractorRequest, register
from ._helpers import (
    form_field_filename,
    parse_multipart,
    safe_json,
    walk_text,
)


_TEXT_KEYS = ("text", "prompt", "message", "content")


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
            if isinstance(data.get("model"), str):
                out.model = data["model"]
        # URL-extracted model for generateContent paths:
        #    /v1beta/models/gemini-1.5-pro:generateContent
        if not out.model and ":generateContent" in req.path:
            try:
                segment = req.path.split("/models/", 1)[1]
                out.model = segment.split(":", 1)[0]
            except Exception:  # pragma: no cover
                pass
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


register("gemini", parse)
