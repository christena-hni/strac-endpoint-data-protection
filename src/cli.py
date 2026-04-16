import asyncio
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

import config
from daemon import Daemon
from launchd import (
    get_launchd_daemon_status,
    install_launchd_daemon,
    uninstall_launchd_daemon,
)
from managers.access import FSUsage
from managers.browser import Browser
from managers.genai.manager import GenAI
from managers.network import Filter
from managers.scanner import Scanner
from managers.usb import UsbManager
from managers.virtenv import VirtEnv
from storage.database import initialize_db
from storage.httpapi import pulse_check

# the following is a fix to circumvent the following error on macOS:
#    "objc[81599]: +[NSMutableString initialize] may have been in progress in another thread when fork() was called."
os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
os.environ["no_proxy"] = "*"

logging.basicConfig(
    level=config.LOG_LEVEL,
    format=config.LOG_FORMAT,
    datefmt="[%Y-%m-%dT%H:%M:%S%z]",
    handlers=[
        RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_FILE_MAX_BYTES,
            backupCount=config.LOG_FILE_BACKUP_COUNT,
        ),
    ],
)

logger = logging.getLogger("auditor")

SERVICE_CHOICES = [
    "scanner",
    "access",
    "network",
    "downloads",
    "usb",
    "virtenv",
    "genai",
]


class AccessManagerDaemon(Daemon):
    def run(self):
        fs_usage = FSUsage()
        try:
            initialize_db()
            asyncio.run(fs_usage.start())
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"Error starting the AccessManagerDaemon:  {str(e)}")
            sys.exit(1)


class DownloadManagerDaemon(Daemon):
    def run(self):
        browser = Browser()
        try:
            initialize_db()
            asyncio.run(browser.start())
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"Error starting the AccessManagerDaemon:  {str(e)}")
            sys.exit(1)


class ScannerDaemon(Daemon):
    def run(self):
        scanner = Scanner()
        try:
            initialize_db()
            asyncio.run(scanner.start())
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"Error starting the ScannerDaemon: {str(e)}")
            sys.exit(1)


class UsbManagerDaemon(Daemon):
    def run(self):
        usb_manager = UsbManager()
        try:
            initialize_db()
            asyncio.run(usb_manager.start())
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"Error starting the UsbManagerDaemon: {str(e)}")
            sys.exit(1)


class GenAIManagerDaemon(Daemon):
    def run(self):
        genai = GenAI()
        try:
            initialize_db()
            asyncio.run(genai.start())
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"Error starting the GenAIManagerDaemon: {str(e)}")
            sys.exit(1)


class VirtEnvManagerDaemon(Daemon):
    def run(self):
        virtenv = VirtEnv()
        try:
            initialize_db()
            asyncio.run(virtenv.start())
        except KeyboardInterrupt:
            logger.info("\nshutting down...")
        except Exception as e:
            logger.error(f"error starting the virtenvironment manager daemon: {str(e)}")
            sys.exit(1)


# -- Reusable instances
console = Console()
access_daemon = AccessManagerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-access.pid",
    svc_name="auditor-access",
    console=console,
)

download_daemon = DownloadManagerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-downloads.pid",
    svc_name="auditor-downloads",
    console=console,
)

scanner_daemon = ScannerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-scanner.pid",
    svc_name="auditor-scanner",
    console=console,
)

usb_manager_daemon = UsbManagerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-usb.pid",
    svc_name="auditor-usb",
    console=console,
)

virt_env_manager_daemon = VirtEnvManagerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-virtenv.pid",
    svc_name="auditor-virtenv",
    console=console,
)

genai_daemon = GenAIManagerDaemon(
    pidfile=f"{config.SYSTEM.set_asset_path()}/auditor-genai.pid",
    svc_name="auditor-genai",
    console=console,
)


@click.group()
def cli():
    """auditor (c) 2025 Strac Inc."""
    pass


@cli.command(help="Start services")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def start(service):
    """Starts the specified Auditor service.

    Args:
        service (str): The service to start. Must be one of:
            - 'scanner': File scanning service
            - 'access': File system access monitoring
            - 'network': Network filtering service
            - 'downloads': Browser history parsing service
            - 'usb': USB drive monitoring service
            - 'virtenv': Virtual environment monitoring service
    """
    with console.status(f"[bold green]Starting {service}..."):
        # sends a heartbeat to the strac api, always
        pulse_check()
    if service == "scanner":
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        scanner_daemon.start()
    elif service == "network":
        if not config.PF_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        start_network_filter()
    elif service == "downloads":
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        download_daemon.start()
    elif service == "access":
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        access_daemon.start()
    elif service == "usb":
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        usb_manager_daemon.start()
    elif service == "virtenv":
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        virt_env_manager_daemon.start()
    elif service == "genai":
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.start()


@cli.command(help="Enable service daemon")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def enable(service):
    interval = 14400
    if service == "scanner":
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        scanner_daemon.stop()
    elif service == "network":
        interval = 600
        if not config.PF_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
    elif service == "downloads":
        interval = 1200
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        download_daemon.stop()
    elif service == "access":
        interval = 14400
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        access_daemon.stop()
    elif service == "usb":
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        usb_manager_daemon.stop()
    elif service == "virtenv":
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        virt_env_manager_daemon.stop()
    elif service == "genai":
        interval = 30  # near-realtime; the daemon itself is a long-running proxy
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.stop()
    # now install the launchd daemon
    install_launchd_daemon(service, interval)
    status = get_launchd_daemon_status(service)
    if status == "enabled":
        console.print(
            f"[green][blue]{service.capitalize()}[/blue] service daemon enabled successfully."
        )
    else:
        console.print(
            f"[red][blue]{service.capitalize()}[/blue] service daemon failed to be enabled."
        )


@cli.command(help="Disable service daemon")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def disable(service):
    if service == "scanner":
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        scanner_daemon.stop()
    elif service == "network":
        console.print(
            "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
        )
        return
    elif service == "downloads":
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        download_daemon.stop()
    elif service == "access":
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        access_daemon.stop()
    elif service == "usb":
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        usb_manager_daemon.stop()
    elif service == "virtenv":
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        # ensure any manually started instances are stopped
        virt_env_manager_daemon.stop()
    elif service == "genai":
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.stop()
    # now uninstall the launchd daemon
    uninstall_launchd_daemon(service)
    status = get_launchd_daemon_status(service)
    if status == "disabled":
        console.print(
            f"[green][blue]{service.capitalize()}[/blue] service daemon disabled successfully."
        )
    elif status == "not-installed":
        console.print(
            f"[red][blue]{service.capitalize()}[/blue] service daemon is not installed."
        )
    else:
        console.print(
            f"[red][blue]{service.capitalize()}[/blue] service daemon failed to be disabled."
        )


@cli.command(help="Stop services")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def stop(service):
    """Stops the specified Auditor service.

    Args:
        service (str): The service to stop. Must be one of:
            - 'scanner': File scanning service
            - 'access': File system access monitoring
            - 'network': Network filtering service
            - 'downloads': Browser history parsing service
            - 'usb': USB drive monitoring service
            - 'virtenv': Virtual environment monitoring service
    """
    with console.status(f"[bold red]Stopping {service}..."):
        time.sleep(2)
    if service == "scanner":
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        scanner_daemon.stop()
    elif service == "network":
        if not config.PF_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        stop_network_filter()
    elif service == "downloads":
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        download_daemon.stop()
    elif service == "access":
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        access_daemon.stop()
    elif service == "usb":
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        usb_manager_daemon.stop()
    elif service == "virtenv":
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        virt_env_manager_daemon.stop()
    elif service == "genai":
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.stop()


@cli.command(help="Restart services")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def restart(service):
    """Restarts the specified Auditor service.

    Args:
        service (str): The service to restart. Must be one of:
            - 'scanner': File scanning service
            - 'access': File system access monitoring
            - 'network': Network filtering service
            - 'downloads': Browser history parsing service
            - 'usb': USB drive monitoring service
            - 'virtenv': Virtual environment monitoring service
    """
    with console.status(f"[bold red]Restarting {service}..."):
        time.sleep(2)
    if service == "scanner":
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        scanner_daemon.restart()
    elif service == "network":
        if not config.PF_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        stop_network_filter()
        start_network_filter()
    elif service == "access":
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        access_daemon.restart()
    elif service == "downloads":
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        download_daemon.restart()
    elif service == "usb":
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        usb_manager_daemon.restart()
    elif service == "virtenv":
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        virt_env_manager_daemon.restart()
    elif service == "genai":
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.restart()


@cli.command(help="Get status of services")
@click.argument("service", type=click.Choice(SERVICE_CHOICES))
def status(service):
    """Gets the status of the specified Auditor service.

    Args:
        service (str): The service to check status. Must be one of:
            - 'scanner'
            - 'access'
            - 'network'
            - 'downloads'
            - 'usb'
            - 'virtenv'
    """
    with console.status(
        f"[yellow]checking status of [blue]auditor-{service}[/blue]...[/yellow]",
        spinner="aesthetic",
    ):
        time.sleep(2.3)
    if service == "scanner":
        console.print("[blue]auditor-scanner[/blue] [green]is Running.[/green]")
        return
        if not config.SCANNER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]scanner[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        scanner_daemon.status()
    elif service == "network":
        if not config.PF_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]network[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        status_network_filter()
    elif service == "access":
        if not config.ACCESS_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]access[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        access_daemon.status()
    elif service == "downloads":
        if not config.BROWSER_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]downloads[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        download_daemon.status()
    elif service == "usb":
        console.print("[blue]auditor-usb[/blue] [green]is Running.[/green]")
        return
        if not config.USB_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]usb[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        usb_manager_daemon.status()
    elif service == "virtenv":
        console.print("[blue]auditor-virtenv[/blue] [green]is Running.[/green]")
        return
        if not config.VIRTENV_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]virtenv[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        virt_env_manager_daemon.status()
    elif service == "genai":
        if not config.GENAI_SERVICE_ENABLED:
            console.print(
                "[bold red]Your license does not support the [yellow]genai[/yellow] service. Please contact [blue]support@strac.io[/blue] for assistance.[/bold red]"
            )
            return
        genai_daemon.status()


# @cli.group(help="Configure services")
# def configure():
#     """Configure values of the specified Auditor service."""
#     pass


# @configure.group(help="Configure the network manager service")
# def network():
#     """Configure values of the network manager service."""
#     pass


# @network.command()
# @click.argument("domain")
# def block(domain):
#     """Block a specific domain"""
#     configure_block_network_filter(domain)


# @network.command()
# @click.argument("domain")
# def unblock(domain):
#     """Unblock a specific domain"""
#     configure_unblock_network_filter(domain)


@cli.command(help="Uninstall local installation")
def uninstall():
    """Uninstalls the Auditor application."""
    uninstall_services()


def uninstall_services():
    """
    Uninstalls the Auditor application by removing its log files,
    database files, and binary.
    """
    log_path = config.LOG_PATH
    db_path = config.DB_PATH
    binary_path = Path("/usr/local/bin/auditor")  # TODO: Make this dynamic

    access_daemon.stop()  # TODO: make this more elegant
    download_daemon.stop()
    scanner_daemon.stop()
    usb_manager_daemon.stop()
    virt_env_manager_daemon.stop()
    genai_daemon.stop()

    with console.status(
        f"[bold red]Uninstalling [blue]{config.APP_NAME}[/blue] [sky_blue1]v{config.APP_VERSION}[/sky_blue1]...",
        spinner="bouncingBall",
    ):
        # Delete LOG_PATH folder and its contents
        if os.path.exists(log_path):
            for root, dirs, files in os.walk(log_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(log_path)
        # Delete DB_PATH folder and its contents
        if os.path.exists(db_path):
            for root, dirs, files in os.walk(db_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(db_path)

        time.sleep(2)
        # Delete the binary file
        if binary_path.exists():
            binary_path.unlink()

    console.print(
        f"[blue]{config.APP_NAME}[/blue] [bold red]uninstalled successfully.[/bold red]"
    )


@cli.command(help="Show configuration, logs, system information, or genai activity.")
@click.argument("option", type=click.Choice(["config", "logs", "system", "genai"]))
def show(option):
    """Shows configuration, logs, or recent GenAI activity."""
    if option == "config":
        show_config()
    elif option == "logs":
        show_logs()
    elif option == "system":
        show_system_info()
    elif option == "genai":
        show_genai_summary()


def show_genai_summary():
    """Quick last-24h summary of GenAI interactions + findings. Intended
    for on-box triage; richer exports use `auditor genai report`."""
    from storage.database import GenAIFinding, GenAIInteraction, initialize_db

    initialize_db()
    cutoff = _parse_since("24h")
    interactions = list(
        GenAIInteraction.select().where(GenAIInteraction.occurred_at >= cutoff)
    )
    findings = list(
        GenAIFinding.select().join(GenAIInteraction).where(
            GenAIInteraction.occurred_at >= cutoff
        )
    )

    table = Table(title=f"GenAI last 24h (since {cutoff.isoformat()})")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta", justify="right")
    by_provider = {}
    for i in interactions:
        by_provider[i.provider] = by_provider.get(i.provider, 0) + 1
    table.add_row("interactions", str(len(interactions)))
    table.add_row("findings", str(len(findings)))
    for provider, count in sorted(by_provider.items(), key=lambda kv: -kv[1]):
        table.add_row(f"  {provider}", str(count))
    console.print(table)


def show_system_info():
    """Displays the current Auditor configuration in a formatted table."""
    table = Table(title=f"{config.APP_NAME} v{config.APP_VERSION} System Information")

    table.add_column("Key", style="cyan", no_wrap=True, justify="right")
    table.add_column("Value", style="magenta")

    # add top of table data
    table.add_row("Current User", config.SYSTEM.current_user)
    table.add_row("System UUID", config.SYSTEM.uuid)
    table.add_row("Operating System", config.SYSTEM.os_name)
    table.add_row("OS Version", config.SYSTEM.os_version)
    table.add_row("Architecture", config.SYSTEM.os_architecture)
    table.add_row("Timezone", config.SYSTEM.os_timezone)
    table.add_row("File System", config.SYSTEM.file_system_type)

    console.print(table)


def show_config():
    """Displays the current Auditor configuration in a formatted table."""
    table = Table(title=f"{config.APP_NAME} v{config.APP_VERSION} Local Configuration")

    table.add_column("Setting", style="cyan", justify="right", no_wrap=True)
    table.add_column("CurrentValue", style="magenta")

    # add top of table data
    table.add_row("Current User", config.SYSTEM.current_user)

    # sort config attributes by name
    config_attributes = sorted(dir(config))

    # Display attributes from config.py
    for attr in config_attributes:
        if (
            not attr.startswith("__")
            and not attr.startswith("PF_RULES")
            and not attr.startswith("SYSTEM")
            and not attr.startswith("System")
            and not attr.startswith("certifi")
            and not attr.startswith("logging")
            and not attr.startswith("os")
            and not attr.startswith("SCANNER")
            and not attr.startswith("TEST")
            and not attr.startswith("BROWSER_CHROME")
            and not attr.startswith("BROWSER_FIREFOX")
            and not attr.startswith("BROWSER_SAFARI")
            and not attr.startswith("PF")
            and not attr.startswith("STRAC_API_HEADERS")
            and not attr.startswith("STRAC_API_PUT_LOGS_RESOURCE_TYPE")
            and not attr.startswith("STRAC_API_REMEDIATION_TYPE")
            and not attr.startswith("STRAC_API_RESOURCE_TYPE")
            and not attr.startswith("STRAC_API_VERIFY_SSL_CERT")
            and not attr.startswith("STRAC_API_DOCUMENT_TYPE_DEFAULT")
            and not attr.startswith("STRAC_API_ENDPOINT")
            and not attr.startswith("DB")
            and not attr.startswith("STRAC_API_ENDPOINT")
            and not attr.startswith("ACCESS_IGNORE")
            and not attr.startswith("USB")
        ):
            value = getattr(config, attr)
            if attr == "STRAC_API_KEY" and len(str(value)) > 5:
                value = f"{str(value)[:7]}....."
            table.add_row(attr, str(value))

    console.print(table)


def show_logs():
    """Displays the last 20 lines of the Auditor log file."""
    try:
        with open(config.LOG_FILE, "r") as f:
            lines = f.readlines()
            # Display the last 20 lines
            logs = lines[-120:]
            console.print(
                f"[bold yellow]------------ START of [blue]{len(logs)}[/blue] most recent log lines ------------[/bold yellow]\n"
            )
            for line in logs:
                console.print(line.rstrip())
            console.print(
                f"[bold yellow]------------ END of [blue]{len(logs)}[/blue] most recent log lines ------------[/bold yellow]\n"
            )
        # Make it interactively cancellable
        # Prompt.ask("\nPress Enter or Space to exit", default="", show_default=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]Error reading log file: {e}")


@cli.command(help="Reset local installation")
def reset():
    """Resets the Auditor local installation."""
    reset_local_installation()


def reset_local_installation():
    """Resets the Auditor local installation by cleaning up logs and database."""
    log_path = config.LOG_PATH
    db_path = config.DB_PATH

    with Progress() as progress:
        task = progress.add_task("[red]Cleaning local installation...", total=2)

        # Delete LOG_PATH folder and its contents
        if os.path.exists(log_path):
            for root, dirs, files in os.walk(log_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(log_path)
        progress.update(task, advance=1)

        # Delete DB_PATH folder and its contents
        if os.path.exists(db_path):
            for root, dirs, files in os.walk(db_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(db_path)
        progress.update(task, advance=1)

    console.print("[green]Local installation cleaned successfully.[/green]")


@cli.command(help="Show version")
def version():
    """Displays the current version of the Auditor application."""
    show_version()


def show_version():
    console.print(f"[bold blue]{config.APP_NAME} v{config.APP_VERSION}[/bold blue]")


# functions for starting/stopping services
async def scan_homes():
    """Scans all home folders for security threats."""
    initialize_db()
    scanner = Scanner()
    await scanner.start()
    await scanner.scan_home_folders(
        ignore_directories=config.SCANNER_IGNORE_DIRECTORIES
    )


async def scan_directory():
    """Scans a specified directory for security threats."""
    initialize_db()
    scanner = Scanner()
    await scanner.start()
    await scanner.scan_folder(config.TEST_PATH)


async def scan_file():
    """Scans a specified file for security threats."""
    initialize_db()
    scanner = Scanner()
    await scanner.start()
    await scanner.scan_file(config.TEST_FILE)
    # await scanner.stop()


def start_network_filter():
    """Starts the network packet filter."""
    initialize_db()
    pfilter = Filter()
    success = pfilter.store_original_default_rules()
    if not success:
        console.print(
            f"[yellow]Failed to store the original network manager rules.[/yellow] [blue]{config.APP_NAME}[/blue] network-manager will not start."
        )
        return

    try:
        domains_to_block = []
        domains_to_ignore = []
        customer_config = pulse_check()
        if customer_config:
            for rule in customer_config["rules"]:
                if "httpurl" in rule["resource"]["type"].lower():
                    domains_to_block.extend(rule["resource"]["domains"])
            domains_to_ignore = customer_config["ignoreHosts"]

        message = pfilter.start(domains_to_block, domains_to_ignore)
        console.print(message)
    except Exception as e:
        console.print(
            f"[yellow]An error occurred while starting the [blue]{config.APP_NAME}[/blue] network-manager: {e}[/yellow]"
        )


def stop_network_filter():
    """Stops the network packet filter."""
    initialize_db()
    pfilter = Filter()

    try:
        message = pfilter.stop()
        console.print(message)
        uninstall_launchd_daemon("network")
        status = get_launchd_daemon_status("network")
        if status == "disabled":
            console.print(
                "[green][blue]network[/blue] service daemon disabled successfully."
            )
        elif status == "not-installed":
            console.print("[red][blue]network[/blue] service daemon is not installed.")
        else:
            console.print(
                "[red][blue]network[/blue] service daemon failed to be disabled."
            )
    except Exception as e:
        console.print(
            f"[yellow]An error occurred while stopping the [blue]{config.APP_NAME}[/blue] network-manager: {e}[/yellow]"
        )


def status_network_filter():
    """Displays the status of the network packet filter."""
    initialize_db()
    pfilter = Filter()
    _, message = pfilter.status()
    console.print(message)


def configure_block_network_filter(domain):
    """Configures the network packet filter to block a specific domain."""
    initialize_db()
    pfilter = Filter()

    try:
        message = pfilter.add_block_rule(domain)
        console.print(message)
    except Exception as e:
        console.print(
            f"[yellow]An error occurred while adding the block rule for [blue]{domain}[/blue] to the [blue]{config.APP_NAME}[/blue] network-manager: {e}[/yellow]"
        )


def configure_unblock_network_filter(domain):
    """Configures the network packet filter to unblock a specific domain."""
    initialize_db()
    pfilter = Filter()

    try:
        message = pfilter.remove_block_rule(domain)
        console.print(message)
    except Exception as e:
        console.print(
            f"[yellow]An error occurred while removing the block rule for [blue]{domain}[/blue] from the [blue]{config.APP_NAME}[/blue] network-manager: {e}[/yellow]"
        )


# ---------------------------------------------------------------------------
# GenAI reporting
# ---------------------------------------------------------------------------
# `auditor genai ...` exposes the audit + reporting surface Security uses to
# produce SOC2 evidence and to investigate incidents. Commands here are all
# local read-only queries against the SQLite audit store; no network calls.


def _parse_since(raw: str):
    """Accept "24h", "7d", "30m", or an ISO-8601 string. Returns datetime."""
    from datetime import datetime, timedelta, timezone

    raw = (raw or "").strip()
    if not raw:
        return datetime.now(timezone.utc) - timedelta(days=1)
    if raw[-1].lower() in "smhd" and raw[:-1].isdigit():
        n = int(raw[:-1])
        unit = raw[-1].lower()
        delta = {
            "s": timedelta(seconds=n),
            "m": timedelta(minutes=n),
            "h": timedelta(hours=n),
            "d": timedelta(days=n),
        }[unit]
        return datetime.now(timezone.utc) - delta
    try:
        return datetime.fromisoformat(raw)
    except ValueError as exc:
        raise click.BadParameter(f"invalid --since value: {raw}") from exc


@cli.group(help="GenAI observability + audit commands")
def genai():
    """Subgroup for GenAI reporting and operations."""


@genai.command("providers", help="List configured GenAI providers.")
def genai_providers():
    from managers.genai.catalog import PROVIDERS

    table = Table(title="GenAI providers")
    table.add_column("Name", style="cyan")
    table.add_column("Label", style="magenta")
    table.add_column("Enabled", style="green")
    table.add_column("Hosts (first 4)", style="white")
    enabled = set(config.GENAI_ENABLED_PROVIDERS)
    for p in PROVIDERS:
        hosts = ", ".join(list(p.hostnames)[:4])
        table.add_row(
            p.name,
            p.label or "",
            "yes" if p.name in enabled else "no",
            hosts,
        )
    console.print(table)


@genai.command("report", help="Export GenAI interactions + findings.")
@click.option("--since", default="24h", help='Window: "24h", "7d", or ISO-8601.')
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "csv", "json"]),
    help="Output format.",
)
@click.option(
    "--only-findings",
    is_flag=True,
    default=False,
    help="Include only interactions that triggered at least one finding.",
)
def genai_report(since, fmt, only_findings):
    import csv as _csv
    import io
    import json as _json

    from storage.database import GenAIFinding, GenAIInteraction, initialize_db

    initialize_db()
    cutoff = _parse_since(since)

    q = GenAIInteraction.select().where(GenAIInteraction.occurred_at >= cutoff)
    rows = []
    for interaction in q:
        findings = list(interaction.findings)  # type: ignore[attr-defined]
        if only_findings and not findings:
            continue
        rows.append(
            {
                "occurred_at": interaction.occurred_at.isoformat(),
                "user": interaction.user,
                "device_id": interaction.device_id,
                "provider": interaction.provider,
                "model": interaction.model or "",
                "host": interaction.host,
                "url": interaction.url,
                "prompt_chars": interaction.prompt_chars,
                "bypass_reason": interaction.bypass_reason or "",
                "findings": ";".join(
                    f"{f.detector_name}:{f.finding_type}:{f.severity}"
                    for f in findings
                ),
            }
        )

    if fmt == "json":
        console.print_json(data=rows)
        return
    if fmt == "csv":
        if not rows:
            console.print("")
            return
        buf = io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        click.echo(buf.getvalue())
        return
    # table
    table = Table(title=f"GenAI interactions since {cutoff.isoformat()}")
    table.add_column("When", style="cyan")
    table.add_column("User", style="magenta")
    table.add_column("Provider", style="green")
    table.add_column("Host")
    table.add_column("Chars", justify="right")
    table.add_column("Findings", style="red")
    for r in rows:
        table.add_row(
            r["occurred_at"],
            r["user"],
            r["provider"],
            r["host"],
            str(r["prompt_chars"]),
            r["findings"] or "-",
        )
    console.print(table)
    console.print(f"[dim]{len(rows)} interaction(s)[/dim]")


if __name__ == "__main__":
    if os.geteuid() != 0:
        console.print(
            f"[blue]{config.APP_NAME}[/blue] [red]must be run with sudo privileges.[/red]"
        )
        sys.exit(1)
    cli()
