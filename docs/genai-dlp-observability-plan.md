# GenAI DLP Observability & Audit — Implementation Plan

> Status: v1 implemented on branch `claude/dlp-observability-plan-xMnQT`.
> See `docs/genai-dlp-runbook.md` for operator procedures.

## Context

Employees across the org are using third-party GenAI tools (ChatGPT,
Claude, Microsoft Copilot, Gemini, Perplexity, etc.) from browsers and
from native desktop apps. Today we have **zero visibility** into what
data is being sent in prompts or file uploads, no DLP enforcement on
that traffic, and no audit trail for SOC2 / HIPAA / customer contractual
commitments. Security needs this shipped fast.

This forked Strac Endpoint Data Protection agent gives us a strong
foundation:

- A plugin architecture (`Managers` / `Processors` / `Detectors`) at `src/`.
- A working `StracApi` client (`src/storage/httpapi.py`) with a ready-made
  `STRAC_API_ENDPOINT_PROCESS_MESSAGE` that we reuse for interaction
  reporting via the new `post_genai_event` method.
- Local SQLite queue / audit store via Peewee (`src/storage/database.py`).
- macOS launchd daemon plumbing (`src/launchd.py`, `src/daemon.py`, `cli.py`).
- A rich detector library (PCI, SSN, IBAN, DOB, email, phone, license,
  passport, confidential keyword, etc.) at `src/detectors/*` — reused
  verbatim to scan prompt text and uploaded files.

The gap closed by this change: the existing `Browser` manager
(`src/managers/browser.py`) only scrapes browser **download history**.
It never saw a prompt or an upload. The `Filter` network manager
(`src/managers/network.py`) is macOS-only PF blocking — useful for
domain blocklists but it cannot inspect content.

Scoping decisions:

- **OS scope**: macOS + Windows for v1.
- **Posture**: Monitor + audit only (no inline blocking) for v1.
- **Channel**: On-endpoint TLS-terminating proxy (required to cover
  native desktop apps like ChatGPT.app, Claude.app, Copilot client,
  Cursor).
- **Apps covered**: Browsers (all) + native desktop AI apps.

## Architecture

One new manager — `GenAI` — runs an on-endpoint, loopback-bound
forwarding HTTPS proxy (mitmproxy embedded as a library). System
HTTP(S) proxy settings are configured via MDM (Jamf profile on macOS,
Intune/GPO on Windows) to route user traffic through the local proxy.
A managed root CA is installed into the system trust store via MDM so
TLS interception is transparent. The proxy only *inspects* traffic
matching the curated GenAI URL catalog; everything else is forwarded
unmodified with no decryption (SNI-based bypass at `tls_clienthello`)
to minimise risk and CPU overhead.

For each intercepted request:

1. Classify by provider via `src/managers/genai/catalog.py`.
2. Parse the request body with the provider-specific extractor in
   `src/managers/genai/extractors/` to get prompt text, conversation id,
   model, and the list of uploaded file parts.
3. Run the extracted text + text uploads through the detector pipeline
   in `src/managers/genai/pipeline.py`. Same detector plug-in pattern as
   the file Scanner; `openai_detector` is explicitly forbidden because
   it egresses candidate text to api.openai.com.
4. Persist `GenAIInteraction` + `GenAIUpload` + `GenAIFinding` rows
   (all redacted — we store SHA-256 + masked preview, never raw values).
5. POST a summary event via `StracApi.post_genai_event`.

Monitor-only means the proxy always passes traffic through; findings
are recorded, never blocked. This eliminates the hardest UX + latency
risks for v1.

### TLS-pinning bypass

A handful of native AI clients pin their own certificates and will
refuse our CA. v1 does not attempt to defeat pinning. The proxy
detects pinning via `tls_failed_client`, adds the SNI to a runtime
bypass set, and writes a `bypass_reason=pinning` interaction row so
Security has visibility. A seed list lives in
`config.GENAI_TLS_PINNING_BYPASS`.

## File map (as shipped)

| Purpose | Path |
| --- | --- |
| New manager entry point | `src/managers/genai/manager.py` |
| mitmproxy wrapper + addon | `src/managers/genai/proxy.py` |
| CA generation + trust install | `src/managers/genai/ca.py` |
| Provider catalog | `src/managers/genai/catalog.py` |
| Per-provider extractors | `src/managers/genai/extractors/*.py` |
| Detector pipeline dispatcher | `src/managers/genai/pipeline.py` |
| New DB models | `src/storage/database.py` |
| Config block | `src/config.py` (new `GENAI_*` section) |
| CLI wiring + reporting | `src/cli.py` |
| Secrets detector | `src/detectors/secrets_detector/` |
| Source-code detector | `src/detectors/source_code_detector/` |
| Strac API helper | `src/storage/httpapi.py` (`post_genai_event`) |
| Windows service wrapper | `src/daemon_windows.py` |
| Windows CA install script | `scripts/windows/install_ca.ps1` |
| Windows MSI build | `Makefile` (`win-installers` target) |
| WiX config | `assets/wix/auditor.wxs` |
| Runbook | `docs/genai-dlp-runbook.md` |

## Explicitly out of scope for v1

- Inline blocking or redaction (deferred to v2).
- Defeating TLS pinning on hostile native apps.
- Linux endpoints.
- Self-hosted replacement for the `openai_detector` (disabled in the
  GenAI pipeline; still available for file scanner).
- Source-code fingerprinting against internal repos (heuristic only in v1).

## Verification

See the runbook for the full end-to-end and pilot acceptance criteria.
Summary: on macOS + Windows pilot machines, send a prompt containing
a test SSN to chatgpt.com, claude.ai, and copilot.microsoft.com; run
`sudo auditor show genai` and `sudo auditor genai report --since 1d
--format csv`; confirm a row per provider with the SSN detector
listed in findings, and a matching event at the Strac backend.
