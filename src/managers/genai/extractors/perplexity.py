"""Extractor for Perplexity traffic.

Perplexity's web app uses a mix of socket.io websockets and straight JSON
POSTs. For v1 we only inspect JSON/form bodies; websocket frames are
logged as URL-only interactions (``bypass_reason=websocket``) so operators
can see they exist without us needing to frame-parse here.
"""

from __future__ import annotations

from . import Extracted, ExtractedUpload, ExtractorRequest, register
from ._helpers import form_field_filename, parse_multipart, safe_json, walk_text


_TEXT_KEYS = ("query", "text", "prompt", "message", "content")


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


register("perplexity", parse)
