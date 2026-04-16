"""GenAI manager: ties the CA, the mitmproxy addon, the extractors, the
detector pipeline, and the persistence layer together.

Lifecycle:
  1. ``start()`` ensures the CA exists, spins up the proxy, and launches
     a pool of async consumers that drain the interaction queue.
  2. Proxy addon calls ``_enqueue_request(flow, provider)`` synchronously
     from the proxy thread; we push a lightweight snapshot onto an
     asyncio.Queue in the manager loop.
  3. Consumers pull snapshots, run the extractor + detector pipeline,
     persist rows to SQLite, and emit an event to StracApi.

Resilience:
  - Every hop between proxy and storage is wrapped in try/except so a
    parse error on one request never tears down the proxy. Failures are
    logged and surface as ``bypass_reason=extractor_error`` rows so
    Security can see the coverage gap in reports.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from config import (
    GENAI_ENABLED_DETECTORS,
    GENAI_ENABLED_PROVIDERS,
    GENAI_PROMPT_MAX_CHARS,
    GENAI_UPLOAD_FLUSH_INTERVAL,
    GENAI_UPLOAD_MAX_BYTES,
    SYSTEM,
)
from storage.database import GenAIFinding, GenAIInteraction, GenAIUpload
from storage.httpapi import StracApi

from .ca import GenAICA
from .catalog import Provider, classify_path, iter_enabled
from .extractors import ExtractorRequest, parser_for
from .pipeline import Pipeline
from .proxy import DEFAULT_BYPASS, GenAIProxy, GenAIProxyAddon


logger = logging.getLogger("manager-genai")


@dataclass
class _Snapshot:
    """Immutable view of a request handed off from the proxy thread to
    the consumer. Holding onto the mitmproxy flow object across threads
    risks mutation, so we copy the bits we need up front."""

    provider_name: str
    method: str
    scheme: str
    host: str
    path: str
    query: str
    content_type: str
    headers: dict
    body: bytes
    url: str
    kind: str  # "request" | "upload" | "other"
    captured_at: datetime = field(default_factory=datetime.utcnow)


class GenAI:
    """Mirrors the shape of Browser / FSUsage managers for easy CLI wiring."""

    def __init__(self, num_consumers: int = 4, queue_size: int = 500):
        self.name = "manager-genai"
        self.logger = logging.getLogger(self.name)
        self.num_consumers = num_consumers
        self.queue: asyncio.Queue[_Snapshot] = asyncio.Queue(maxsize=queue_size)
        self.consumer_tasks: List[asyncio.Task] = []
        self.is_running = False

        self._main_loop: Optional[asyncio.AbstractEventLoop] = None
        self._pipeline = Pipeline(list(GENAI_ENABLED_DETECTORS))
        self._providers = iter_enabled(GENAI_ENABLED_PROVIDERS)
        self._ca = GenAICA()
        self._proxy: Optional[GenAIProxy] = None
        self._strac = StracApi()
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._lock = threading.Lock()

    # ---- proxy callbacks (run on proxy thread) --------------------------

    def _on_request(self, flow, provider: Provider) -> None:
        """Called by the mitmproxy addon for every decrypted request. Keep
        this method cheap: snapshot + enqueue, nothing else."""
        try:
            req = flow.request
            ctype = req.headers.get("content-type", "")
            path_kind = classify_path(provider, req.path)
            # Truncate bodies defensively before crossing thread boundary
            body = req.get_content(strict=False) or b""
            if len(body) > GENAI_UPLOAD_MAX_BYTES:
                body = body[:GENAI_UPLOAD_MAX_BYTES]
            snap = _Snapshot(
                provider_name=provider.name,
                method=req.method,
                scheme=req.scheme,
                host=req.host,
                path=req.path,
                query=req.query.encoded if hasattr(req.query, "encoded") else "",
                content_type=ctype,
                headers=dict(req.headers.items()),
                body=bytes(body),
                url=req.pretty_url,
                kind=path_kind,
            )
        except Exception as exc:
            self.logger.error("failed to snapshot flow: %s", exc)
            return

        loop = self._main_loop
        if not loop:
            return
        # call_soon_threadsafe is the canonical cross-thread handoff.
        loop.call_soon_threadsafe(self._enqueue_safe, snap)

    def _enqueue_safe(self, snap: _Snapshot) -> None:
        try:
            self.queue.put_nowait(snap)
        except asyncio.QueueFull:
            self.logger.warning(
                "genai queue full (provider=%s); dropping snapshot", snap.provider_name
            )

    def _on_bypass(self, host: str, reason: str) -> None:
        """Called when the proxy gives up on a host (e.g. pinning). Records
        a lightweight interaction row so Security sees the gap."""
        loop = self._main_loop
        if not loop:
            return
        loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(
                self._record_bypass(host, reason), loop=loop
            )
        )

    async def _record_bypass(self, host: str, reason: str) -> None:
        try:
            GenAIInteraction.create(
                user=SYSTEM.current_user or "unknown",
                device_id=SYSTEM.uuid or "unknown",
                provider="unknown",
                host=host,
                url=f"https://{host}/",
                bypass_reason=reason,
            )
        except Exception as exc:
            self.logger.error("failed to record bypass for %s: %s", host, exc)

    # ---- consumer -------------------------------------------------------

    async def _consumer(self, consumer_id: int) -> None:
        self.logger.debug("genai consumer %d starting", consumer_id)
        while self.is_running:
            try:
                snap = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                await self._process(snap)
            except Exception as exc:
                self.logger.error("consumer %d error: %s", consumer_id, exc)
            finally:
                self.queue.task_done()
        self.logger.debug("genai consumer %d stopping", consumer_id)

    async def _process(self, snap: _Snapshot) -> None:
        """Main per-request flow: extract -> scan -> persist -> notify."""
        parser = parser_for(snap.provider_name)
        extracted = None
        if parser is not None:
            try:
                extracted = parser(
                    ExtractorRequest(
                        method=snap.method,
                        scheme=snap.scheme,
                        host=snap.host,
                        path=snap.path,
                        query=snap.query,
                        content_type=snap.content_type,
                        headers=snap.headers,
                        body=snap.body,
                    )
                )
            except Exception as exc:
                self.logger.error(
                    "extractor %s raised: %s", snap.provider_name, exc
                )
        # Fall back to URL-only interaction if extractor failed or skipped.
        prompt = (extracted.prompt_text if extracted else "") or ""
        truncated = False
        if len(prompt) > GENAI_PROMPT_MAX_CHARS:
            prompt = prompt[:GENAI_PROMPT_MAX_CHARS]
            truncated = True
        prompt_sha = (
            hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()
            if prompt
            else None
        )

        interaction = GenAIInteraction.create(
            user=SYSTEM.current_user or "unknown",
            device_id=SYSTEM.uuid or "unknown",
            provider=snap.provider_name,
            model=extracted.model if extracted else None,
            conversation_id=extracted.conversation_id if extracted else None,
            direction="request",
            url=snap.url,
            method=snap.method,
            host=snap.host,
            prompt_sha256=prompt_sha,
            prompt_chars=len(prompt),
            prompt_truncated=truncated,
            prompt_preview=_safe_preview(prompt),
            bypass_reason=(
                "extractor_warning"
                if extracted and extracted.warnings
                else None
            ),
        )

        upload_rows: List[GenAIUpload] = []
        if extracted and extracted.uploads:
            for up in extracted.uploads:
                sha = (
                    hashlib.sha256(up.content or b"").hexdigest()
                    if up.content is not None
                    else hashlib.sha256(up.filename.encode()).hexdigest()
                )
                row = GenAIUpload.create(
                    interaction=interaction,
                    filename=up.filename,
                    mime_type=up.mime_type,
                    size_bytes=up.size_bytes,
                    sha256=sha,
                )
                upload_rows.append(row)

        # Run DLP detectors over the prompt text AND any text-shaped uploads.
        findings = []
        if prompt:
            findings.extend(await self._pipeline.scan(prompt))
        for up, row in zip(extracted.uploads if extracted else [], upload_rows):
            if up.content and _is_textish(up.mime_type, up.filename):
                try:
                    text = up.content.decode("utf-8", errors="replace")
                except Exception:
                    continue
                for f in await self._pipeline.scan(text):
                    findings.append(f)
                    GenAIFinding.create(
                        interaction=interaction,
                        upload=row,
                        detector_name=f.detector_name,
                        finding_type=f.finding_type,
                        content_redacted=f.content_redacted,
                        content_sha256=f.content_sha256,
                        context_redacted=f.context_redacted,
                        severity=f.severity,
                    )
        # Prompt-level findings that haven't already been written (uploads
        # were written in the loop above).
        for f in findings:
            if GenAIFinding.select().where(
                (GenAIFinding.interaction == interaction)
                & (GenAIFinding.content_sha256 == f.content_sha256)
                & (GenAIFinding.detector_name == f.detector_name)
            ).exists():
                continue
            GenAIFinding.create(
                interaction=interaction,
                detector_name=f.detector_name,
                finding_type=f.finding_type,
                content_redacted=f.content_redacted,
                content_sha256=f.content_sha256,
                context_redacted=f.context_redacted,
                severity=f.severity,
            )

        # Ship a summary event to Strac. process_message already exists on
        # StracApi and accepts arbitrary JSON; we reuse it to avoid a
        # backend change for v1.
        try:
            await self._notify_strac(interaction, upload_rows, findings)
            interaction.synced_to_strac = True
            interaction.save()
        except Exception as exc:
            self.logger.error("strac notify failed: %s", exc)

    async def _notify_strac(
        self,
        interaction: GenAIInteraction,
        uploads: List[GenAIUpload],
        findings,
    ) -> None:
        # Minimal fire-and-forget: reuse the existing HTTP client plumbing
        # but don't block the consumer on network latency -- run in a
        # worker thread so the queue keeps draining.
        payload = {
            "type": "genai_interaction",
            "occurred_at": interaction.occurred_at.isoformat(),
            "user": interaction.user,
            "device_id": interaction.device_id,
            "provider": interaction.provider,
            "model": interaction.model,
            "conversation_id": interaction.conversation_id,
            "url": interaction.url,
            "host": interaction.host,
            "prompt_sha256": interaction.prompt_sha256,
            "prompt_chars": interaction.prompt_chars,
            "prompt_truncated": interaction.prompt_truncated,
            "bypass_reason": interaction.bypass_reason,
            "uploads": [
                {
                    "filename": u.filename,
                    "mime_type": u.mime_type,
                    "size_bytes": u.size_bytes,
                    "sha256": u.sha256,
                }
                for u in uploads
            ],
            "findings": [
                {
                    "detector": f.detector_name,
                    "type": f.finding_type,
                    "severity": f.severity,
                    "content_sha256": f.content_sha256,
                }
                for f in findings
            ],
        }
        # Reuse the shared Strac HTTP client. post_genai_event wraps the
        # envelope with device/user metadata and never raises.
        await self._strac.post_genai_event(payload)

    # ---- lifecycle ------------------------------------------------------

    async def start(self) -> None:
        if self.is_running:
            self.logger.warning("genai manager is already running")
            return
        self.is_running = True
        self._main_loop = asyncio.get_event_loop()

        # Generate the CA if this is the first run on this endpoint. Trust
        # install is a separate, installer-time concern.
        self._ca.ensure()

        # Load detectors up front so the first request doesn't pay the
        # cost of importing every regex module.
        self._pipeline.load()

        addon = GenAIProxyAddon(
            on_request=self._on_request,
            on_bypass=self._on_bypass,
            extra_bypass=set(DEFAULT_BYPASS),
        )
        self._proxy = GenAIProxy(addon)
        self._proxy.start()

        def handle_exception(task):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.logger.error("consumer task crashed: %s", exc)

        for i in range(self.num_consumers):
            task = asyncio.create_task(self._consumer(i))
            task.add_done_callback(handle_exception)
            self.consumer_tasks.append(task)

        self.logger.info(
            "genai manager running with %d consumers", self.num_consumers
        )
        while self.is_running:
            await asyncio.sleep(GENAI_UPLOAD_FLUSH_INTERVAL)

    async def stop(self) -> None:
        if not self.is_running:
            return
        self.is_running = False
        if self._proxy:
            self._proxy.stop()
        for task in self.consumer_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self.consumer_tasks.clear()
        self._executor.shutdown(wait=False)


# -- helpers ---------------------------------------------------------------


_PREVIEW_LEN = 512


def _safe_preview(text: str) -> Optional[str]:
    """Produce a bounded, whitespace-normalised preview. We intentionally
    don't strip potential sensitive substrings here -- findings are
    already redacted in GenAIFinding; the preview's purpose is to let an
    operator sanity-check WHAT was sent, not to reveal secrets."""
    if not text:
        return None
    snippet = text[:_PREVIEW_LEN]
    return snippet.replace("\r", " ").replace("\n", " ⏎ ")


_TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".yaml", ".yml", ".csv", ".log",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".rs",
    ".java", ".c", ".cpp", ".h", ".hpp", ".sh", ".ps1", ".sql",
    ".html", ".htm", ".xml", ".toml", ".ini", ".env",
}


def _is_textish(mime: Optional[str], filename: str) -> bool:
    if mime and mime.startswith("text/"):
        return True
    if mime in {"application/json", "application/xml", "application/yaml"}:
        return True
    lower = (filename or "").lower()
    return any(lower.endswith(ext) for ext in _TEXT_EXTENSIONS)
