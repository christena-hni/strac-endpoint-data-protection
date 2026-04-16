"""Regex-only fallback extractor.

Used for long-tail providers (you.com, poe.com, meta.ai, mistral.ai,
character.ai, cursor.sh, codeium.com, ...) where writing a bespoke parser
isn't worth the maintenance cost. We opportunistically parse JSON with a
broad set of text keys; if that fails we still record a URL-only
interaction so operators see the visit in the audit log.
"""

from __future__ import annotations

from . import Extracted, ExtractedUpload, ExtractorRequest, register
from ._helpers import form_field_filename, parse_multipart, safe_json, walk_text


_TEXT_KEYS = (
    "text", "content", "prompt", "message", "query", "input",
    "question", "userInput", "user_input", "body",
)


def parse(req: ExtractorRequest) -> Extracted:
    out = Extracted()
    ctype = (req.content_type or "").lower()

    if "application/json" in ctype:
        data = safe_json(req.body)
        if data is None:
            out.warnings.append("body was not valid JSON")
            return out
        out.prompt_text = "\n".join(walk_text(data, _TEXT_KEYS))
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

    # text/plain bodies: scan as-is (Cursor/Codeium occasionally do this).
    if "text/" in ctype and req.body:
        try:
            out.prompt_text = req.body.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover
            pass
        return out

    out.warnings.append(f"unhandled content-type: {ctype or 'n/a'}")
    return out


register("generic", parse)
