"""Windows-service wrapper analogous to ``src/daemon.py``.

The posix Daemon class uses double-fork + pidfile; that doesn't exist on
Windows. Instead we integrate with the Service Control Manager via
``pywin32``'s ``win32serviceutil.ServiceFramework``. One ``WindowsDaemon``
subclass per manager (access, genai, etc.) lets us share an install /
start / stop / status surface with the posix code path.

Consumers subclass ``WindowsDaemon`` and override ``run()``, mirroring
``Daemon``. ``cli.py`` picks between the two at runtime via
``SYSTEM.OS_IS_WINDOWS``.

This module imports pywin32 lazily so the mac/linux code paths don't fail
at import when pywin32 isn't installed.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Optional


logger = logging.getLogger("daemon-windows")


def _load_pywin32():
    """Lazy-import pywin32. Raises at call-site if missing so the error
    is visible rather than silent."""
    try:
        import servicemanager  # noqa: F401
        import win32event
        import win32service
        import win32serviceutil
    except ImportError as exc:  # pragma: no cover - platform gate
        raise ImportError(
            "pywin32 is required on Windows; "
            "install with `python -m pip install pywin32` and reboot "
            "or run `python -m pywin32_postinstall -install`"
        ) from exc
    return win32event, win32service, win32serviceutil


class WindowsDaemon:
    """Shape-compatible with posix ``Daemon`` so cli.py can treat them
    interchangeably. ``run()`` must be overridden by subclasses."""

    # Subclasses override
    _svc_name_ = "AuditorService"
    _svc_display_name_ = "Strac Auditor"
    _svc_description_ = "Strac Endpoint Data Protection"

    def __init__(
        self,
        pidfile: Optional[str] = None,
        svc_name: Optional[str] = None,
        console=None,
        **_ignored,
    ):
        self.console = console
        if svc_name:
            # service names on Windows can't contain dashes; normalise
            self._svc_name_ = svc_name.replace("-", "")
            self._svc_display_name_ = svc_name
        self._stop_event: Optional[object] = None
        self._runner_thread: Optional[threading.Thread] = None

    # -- hooks -----------------------------------------------------------

    def run(self):
        """Override in subclass (e.g. AccessManagerDaemon, GenAIDaemon)."""
        raise NotImplementedError

    # -- lifecycle API mirrors posix Daemon -----------------------------

    def start(self):
        """Either run inline (interactive mode) or hand control to the
        SCM (service mode). cli.py calls this on `auditor start <svc>`."""
        logger.info("starting %s", self._svc_name_)
        try:
            self.run()
        except KeyboardInterrupt:
            logger.info("interrupted")

    def stop(self):
        """Signals the in-process runner to unwind if one exists."""
        logger.info("stopping %s", self._svc_name_)
        if self._stop_event is not None:
            try:
                import win32event
                win32event.SetEvent(self._stop_event)
            except Exception as exc:  # pragma: no cover
                logger.error("stop signal failed: %s", exc)

    def restart(self):
        self.stop()
        self.start()

    def status(self):
        win32event, win32service, win32serviceutil = _load_pywin32()
        try:
            status = win32serviceutil.QueryServiceStatus(self._svc_name_)
            running = status[1] == win32service.SERVICE_RUNNING
            label = "running" if running else "stopped"
        except Exception as exc:
            label = f"unknown ({exc})"
        if self.console:
            self.console.print(f"[blue]{self._svc_name_}[/blue] is {label}.")
        return label

    # -- SCM integration -------------------------------------------------

    def install(self, args=None):
        """Register the service with the SCM. Invoked by the MSI
        postinstall and by `auditor enable <svc>` on Windows."""
        _, _, win32serviceutil = _load_pywin32()
        win32serviceutil.InstallService(
            pythonClassString=f"{self.__class__.__module__}.{self.__class__.__name__}",
            serviceName=self._svc_name_,
            displayName=self._svc_display_name_,
            description=self._svc_description_,
            startType=0x2,  # SERVICE_AUTO_START
        )
        logger.info("installed service %s", self._svc_name_)

    def uninstall(self):
        _, _, win32serviceutil = _load_pywin32()
        win32serviceutil.RemoveService(self._svc_name_)
        logger.info("removed service %s", self._svc_name_)


# ---- Concrete daemons ----------------------------------------------------
# Mirror the classes in src/cli.py so Windows can reuse them. Each just
# reroutes to the manager's async start() in the same way.


class WindowsGenAIDaemon(WindowsDaemon):
    _svc_name_ = "AuditorGenAI"
    _svc_display_name_ = "Auditor GenAI"
    _svc_description_ = "Observability + DLP for third-party GenAI tools"

    def run(self):
        import asyncio

        from managers.genai.manager import GenAI
        from storage.database import initialize_db

        try:
            initialize_db()
            asyncio.run(GenAI().start())
        except KeyboardInterrupt:
            logger.info("shutting down")
        except Exception as exc:
            logger.error("GenAI daemon crashed: %s", exc)
            sys.exit(1)
