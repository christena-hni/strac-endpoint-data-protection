# GenAI DLP — Operator Runbook

Operational reference for the `auditor-genai` service. For the "why" and
the implementation plan, see `docs/genai-dlp-observability-plan.md`.

## Quick reference

| Task | Command |
| --- | --- |
| Start (macOS) | `sudo auditor start genai` |
| Stop (macOS) | `sudo auditor stop genai` |
| Status | `sudo auditor status genai` |
| Last-24h summary | `sudo auditor show genai` |
| CSV export | `sudo auditor genai report --since 7d --format csv > out.csv` |
| List providers | `sudo auditor genai providers` |
| Start (Windows, admin) | `Start-Service AuditorGenAI` |

The manager is also installed as a launchd daemon (macOS) / service
(Windows) by the installer, so reboots don't require a manual start.

## Deployment checklist (pilot)

1. **Build + sign installers.**
   - macOS: `make CUSTOMER=<client> arm-macos-installers`
   - Windows: `make CUSTOMER=<client> win-installers` on a Windows host
     with WiX Toolset + signtool configured.

2. **Push the installer via MDM.**
   - Jamf: upload the `.pkg`; scope to pilot group.
   - Intune: upload the `.msi`; require install on-enrol.

3. **Push system proxy configuration via MDM.**
   - macOS Jamf profile: set `HTTPProxy` + `HTTPSProxy` to
     `127.0.0.1:8119`, exclude `localhost` and RFC1918.
   - Windows GPO: `Computer Configuration → Admin Templates → Network →
     Windows HTTP Services → WinHTTP Proxy` set to
     `http=127.0.0.1:8119;https=127.0.0.1:8119`.

4. **Confirm the root CA landed.**
   - macOS: `security find-certificate -c "Strac Auditor Root" \
     /Library/Keychains/System.keychain`
   - Windows: `Get-ChildItem Cert:\LocalMachine\Root | ? Subject -match 'Strac Auditor Root'`

5. **Push an acceptable-AI-use policy + employee notice.** Required
   pre-rollout in EU (works council) and recommended everywhere. The
   banner should explain that prompts + file uploads to third-party AI
   services are audited for DLP purposes.

6. **Sanity-check on one pilot box.** See "E2E validation" below.

## E2E validation (per-endpoint)

Run through this after installation, and once per week during the pilot
on a sample endpoint.

### macOS

```bash
# 1. Daemon running?
sudo auditor status genai
# expected: "running as it should be"

# 2. Proxy listening on the expected port?
lsof -nP -iTCP:8119 -sTCP:LISTEN
# expected: the auditor binary

# 3. CA trusted?
security find-certificate -c "Strac Auditor Root" \
    /Library/Keychains/System.keychain >/dev/null && echo OK

# 4. Exercise each provider
#    - Open Chrome -> chatgpt.com -> send "My SSN is 123-45-6789"
#    - Open Claude.app (native) -> send a paragraph containing a PAN
#      (4111 1111 1111 1111)
#    - Open Edge -> copilot.microsoft.com -> attach a PDF with a TIN

# 5. Verify captured rows
sudo auditor show genai
# expected: >=1 row per provider, with findings listed

# 6. Export SOC2-grade evidence
sudo auditor genai report --since 1h --format csv
```

### Windows

```powershell
Get-Service AuditorGenAI
# expected: Running

Get-NetTCPConnection -LocalPort 8119 -State Listen
# expected: one connection, OwningProcess = auditor.exe

Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object Subject -match "Strac Auditor Root"
# expected: one cert

# repeat the exercise + report steps from the macOS section with sudo
# swapped for an elevated PowerShell prompt.
```

## TLS pinning — known bypass list

Track new pinning discoveries here. The proxy will *auto-add* these to
the runtime bypass set, but seeding `config.GENAI_TLS_PINNING_BYPASS`
reduces noise on first connection.

| Host | Discovered | Notes |
| --- | --- | --- |
| `updates.anthropic.com` | 2026-Q2 | Auto-update channel; not prompts |
| `downloads.anthropic.com` | 2026-Q2 | Installer host; not prompts |

If a host pins AND it's a prompt-carrying host (rare), open a ticket
tagged `genai-coverage-gap`; pilot ops will decide between (a) excluding
the app from the pilot and (b) deferring v2 pinning bypass work to
cover it.

## Detector tuning

Detectors live at `src/detectors/<name>/<name>.py`. Each exposes
`async process_text(text) -> [{type, content, context}]`. To add one:

1. Create `src/detectors/<new>/<new>.py` with a `Detector` class.
2. Add `<new>` to `config.GENAI_ENABLED_DETECTORS` (and
   `SCANNER_ENABLED_DETECTORS` if it should also run on files).
3. `src/managers/genai/pipeline.py:_SEVERITY` — add a severity entry.
4. Ship.

To tune an existing detector (e.g. SSN false positives):

1. Edit the regex / keyword list in `<name>_detector.py`.
2. Add a golden test under `tests/detectors/<name>/` (happy + edge).
3. Run `pytest` locally before commit.

## Data retention + privacy

| Store | Retention | Notes |
| --- | --- | --- |
| Local SQLite (`GenAIInteraction` et al.) | 30 days rolling, vacuum weekly | Configure via a `cron` + `sqlite3` DELETE |
| Strac backend | Per contract | Default is 90 days; ask Strac CS |
| CA private key (`strac-auditor-root.key`) | Indefinitely (per endpoint) | 0o600 on disk; regenerated if removed |

We intentionally do **not** store the raw prompt text or raw file
contents locally. `prompt_preview` is a bounded, whitespace-normalised
first-512-chars slice; findings carry SHA-256 + masked preview, not raw
matches. This keeps the audit log itself from becoming a secondary leak
of the secrets it's meant to detect.

## Incident response

On finding of severity `critical` (secrets or PCI):

1. Pull the matching row:
   `sudo auditor genai report --since 24h --only-findings --format json`
2. Confirm via SHA-256 of the suspected exposed value (operator retypes
   it, hashes locally, compares to `content_sha256`).
3. If confirmed, engage the standard credential-rotation runbook:
   revoke the key at the issuer, rotate, audit dependent services.
4. Log the incident in Strac; use `event_id` as the cross-reference.

## Troubleshooting

**"Users report HTTPS warnings in the browser."**
The CA didn't install. Re-run `install_ca.ps1` or the `security
add-trusted-cert` command. Confirm via step 3 of E2E validation.

**"Proxy is up but no rows appear."**
System proxy isn't pointing at 127.0.0.1:8119. Check MDM deployment
state. Fallback: set per-user proxy in Network settings for a sanity
check.

**"Prompts captured but no findings on known-sensitive content."**
Detector set is misconfigured or the relevant detector's regex is too
strict. Inspect `config.GENAI_ENABLED_DETECTORS` and compare with the
Scanner's working set.

**"A new AI tool we care about isn't captured."**
Add the hostname + request-path regex to `catalog.py:PROVIDERS` and, if
the body shape is unusual, add a new module under `extractors/`. Ship.
Existing interactions will start showing up on the next flow.
