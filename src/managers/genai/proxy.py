"""mitmproxy integration for the GenAI manager.

We embed mitmproxy as a library rather than shelling out to the CLI tool:
  - Single daemon process, same lifecycle as the rest of the manager.
  - No subprocess <-> Python IPC to maintain.
  - We can register an async addon directly on DumpMaster.

Host-based decrypt policy:

  mitmproxy decrypts every HTTPS flow by default. We flip this around via
  ``tls.passthrough``: we look at SNI during CONNECT and ONLY decrypt
  hosts in our catalog. Everything else is forwarded untouched. This is
  critical both for privacy (we never see bank.com traffic) and CPU.

Pinning handling:

  When a host's client pins its cert, the TLS handshake will fail *after*
  we've already answered CONNECT. We catch the tls_failed hook, add the
  SNI to a runtime bypass set, and log a bypass_reason=pinning event so
  Security has visibility. Subsequent connections to that host pass
  through without decryption for the lifetime of the proxy.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Callable, Optional, Set

from config import (
    GENAI_PROXY_HOST,
    GENAI_PROXY_PORT,
    GENAI_TLS_PINNING_BYPASS,
    SYSTEM,
)

from .catalog import all_hostnames, match_host

logger = logging.getLogger("manager-genai-proxy")


class GenAIProxyAddon:
    """mitmproxy addon that forwards every matching flow to a callback.

    The manager passes in ``on_request`` (called with the intercepted
    request metadata + body) and ``on_pinning`` (called when we decide to
    stop decrypting a given host). Both are invoked from the mitmproxy
    asyncio loop, so they should be cheap -- heavy lifting happens on
    the manager's own consumer loop.
    """

    def __init__(
        self,
        on_request: Callable,
        on_bypass: Callable,
        extra_bypass: Optional[Set[str]] = None,
    ):
        self._on_request = on_request
        self._on_bypass = on_bypass
        self._decrypt_hosts = all_hostnames()
        self._pinned: Set[str] = set(extra_bypass or [])

    # ---- mitmproxy hooks ------------------------------------------------

    def tls_clienthello(self, data):
        """Decide whether to decrypt. Called during the TLS handshake."""
        sni = (data.client_hello.sni or "").lower()
        # Suffix-match so subdomains of enabled providers are covered.
        should_decrypt = False
        if sni in self._decrypt_hosts:
            should_decrypt = True
        else:
            for host in self._decrypt_hosts:
                if sni.endswith(f".{host}"):
                    should_decrypt = True
                    break
        if sni in self._pinned:
            should_decrypt = False
        if not should_decrypt:
            # This is the mitmproxy v10+ API: setting ignore_connection on
            # the data object bypasses decryption for this connection.
            data.ignore_connection = True

    def tls_failed_client(self, data):
        """TLS handshake to our upstream server failed -- most likely the
        client pinned. Add to the runtime bypass set."""
        sni = (getattr(data, "sni", None) or "").lower()
        if sni and sni not in self._pinned:
            self._pinned.add(sni)
            logger.warning("tls handshake failed for %s; adding to bypass", sni)
            try:
                self._on_bypass(sni, reason="pinning")
            except Exception as exc:  # pragma: no cover
                logger.error("on_bypass callback failed: %s", exc)

    def request(self, flow):
        """Called for every *decrypted* HTTP request."""
        try:
            provider = match_host(flow.request.host)
            if provider is None:
                # Shouldn't happen -- SNI gate above should have stopped us
                # decrypting -- but be defensive.
                return
            self._on_request(flow, provider)
        except Exception as exc:
            logger.error("on_request callback raised: %s", exc)


class GenAIProxy:
    """Thin wrapper around mitmproxy.tools.dump.DumpMaster.

    Runs the proxy in its own asyncio loop on a background thread so it
    doesn't interfere with the manager's own loop. Shutdown is cooperative
    via ``master.shutdown()``.
    """

    def __init__(self, addon: GenAIProxyAddon):
        self._addon = addon
        self._master = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("proxy already running")
            return

        started = threading.Event()

        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            try:
                # Lazy import: mitmproxy is a heavy dep we don't want to
                # pay for in unit tests that only touch the catalog.
                from mitmproxy.options import Options
                from mitmproxy.tools.dump import DumpMaster

                asset = SYSTEM.set_asset_path()
                opts = Options(
                    listen_host=GENAI_PROXY_HOST,
                    listen_port=GENAI_PROXY_PORT,
                    confdir=asset,
                    # Use our own CA material. mitmproxy expects a combined
                    # key + cert PEM under confdir as mitmproxy-ca.pem.
                    ssl_insecure=False,
                )
                master = DumpMaster(
                    opts,
                    with_termlog=False,
                    with_dumper=False,
                )
                master.addons.add(self._addon)
                self._master = master
                started.set()
                loop.run_until_complete(master.run())
            except Exception as exc:
                logger.error("proxy thread crashed: %s", exc, exc_info=True)
                started.set()
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        self._thread = threading.Thread(
            target=_run, name="genai-proxy", daemon=True
        )
        self._thread.start()
        started.wait(timeout=30)
        logger.info(
            "genai proxy listening on %s:%d", GENAI_PROXY_HOST, GENAI_PROXY_PORT
        )

    def stop(self) -> None:
        if not self._master:
            return
        try:
            self._loop.call_soon_threadsafe(self._master.shutdown)
        except Exception as exc:
            logger.error("failed to signal proxy shutdown: %s", exc)
        if self._thread:
            self._thread.join(timeout=10)
        self._master = None
        self._thread = None
        self._loop = None


# Convenience: the default pinning bypass list merges config + a runtime
# set we build as we discover pinned hosts.
DEFAULT_BYPASS = set(GENAI_TLS_PINNING_BYPASS)
