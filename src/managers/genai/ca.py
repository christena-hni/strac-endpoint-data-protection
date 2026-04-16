"""Root CA lifecycle for the GenAI TLS-terminating proxy.

Responsibilities:
  - Generate a per-install 4096-bit RSA root CA the first time the manager
    starts, and persist the key + cert under SYSTEM.set_asset_path() so it
    survives upgrades.
  - Expose install_trust() / uninstall_trust() which shell out to the OS-
    native trust tooling (security(1) on macOS, certutil on Windows).
  - Expose paths mitmproxy can load via --set confdir=... and
    --set certs=...

Design notes:
  - We do NOT embed a shared/static CA. Each endpoint mints its own so a
    leak of one device's CA cannot be used to MITM another. The key never
    leaves the asset directory and is 0o600 there.
  - install_trust() is invoked only from the installer postinstall script,
    not from everyday "auditor start genai" calls, because it requires
    elevated privileges and is a one-time operation per endpoint.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import (
    GENAI_CA_CERT_FILENAME,
    GENAI_CA_COMMON_NAME,
    GENAI_CA_KEY_FILENAME,
    GENAI_CA_VALIDITY_DAYS,
    SYSTEM,
)

logger = logging.getLogger("manager-genai-ca")


class GenAICA:
    """Encapsulates the proxy's root CA material.

    The ``cryptography`` package is imported lazily so unit tests for the
    surrounding code (catalog, extractors) don't pay for a heavy dep at
    import time.
    """

    def __init__(self, asset_dir: str | None = None):
        self.asset_dir = Path(asset_dir or SYSTEM.set_asset_path())
        self.cert_path = self.asset_dir / GENAI_CA_CERT_FILENAME
        self.key_path = self.asset_dir / GENAI_CA_KEY_FILENAME

    # ---- material -------------------------------------------------------

    def exists(self) -> bool:
        return self.cert_path.is_file() and self.key_path.is_file()

    def ensure(self) -> None:
        """Generate the CA if it doesn't already exist. Idempotent."""
        if self.exists():
            logger.debug("ca already present at %s", self.cert_path)
            return
        self._generate()

    def _generate(self) -> None:
        logger.info("generating new GenAI root CA at %s", self.cert_path)
        # Lazy import: heavy optional dep.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Strac"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Auditor"),
                x509.NameAttribute(NameOID.COMMON_NAME, GENAI_CA_COMMON_NAME),
            ]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=GENAI_CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(private_key=key, algorithm=hashes.SHA256())
        )

        self.asset_dir.mkdir(parents=True, exist_ok=True)
        self.cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        self.key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(self.key_path, 0o600)
            os.chmod(self.cert_path, 0o644)
        except OSError as exc:  # pragma: no cover - Windows
            logger.debug("chmod failed (%s); non-fatal on Windows", exc)

    # ---- trust store integration ----------------------------------------

    def install_trust(self) -> bool:
        """Install the CA into the system trust store. Requires root/admin.

        Returns True on success. Idempotent -- safe to call repeatedly.
        """
        if not self.exists():
            self.ensure()
        system = platform.system()
        if system == "Darwin":
            return self._install_trust_macos()
        if system == "Windows":
            return self._install_trust_windows()
        logger.warning("install_trust: unsupported platform %s", system)
        return False

    def uninstall_trust(self) -> bool:
        system = platform.system()
        if system == "Darwin":
            return self._uninstall_trust_macos()
        if system == "Windows":
            return self._uninstall_trust_windows()
        return False

    def _install_trust_macos(self) -> bool:
        # Adding to /Library/Keychains/System.keychain makes the CA
        # trusted system-wide (every user, every browser that respects
        # the keychain, every Electron app).
        cmd = [
            "/usr/bin/security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            str(self.cert_path),
        ]
        logger.info("installing CA into macOS System keychain: %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("macOS CA install failed: %s", exc.stderr)
            return False

    def _uninstall_trust_macos(self) -> bool:
        cmd = [
            "/usr/bin/security",
            "remove-trusted-cert",
            "-d",
            str(self.cert_path),
        ]
        logger.info("removing CA from macOS System keychain")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("macOS CA uninstall failed: %s", exc.stderr)
            return False

    def _install_trust_windows(self) -> bool:
        cmd = ["certutil.exe", "-addstore", "-f", "ROOT", str(self.cert_path)]
        logger.info("installing CA into Windows Root store")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("Windows CA install failed: %s", exc)
            return False

    def _uninstall_trust_windows(self) -> bool:
        # We identify the cert to delete by its common name.
        cmd = ["certutil.exe", "-delstore", "ROOT", GENAI_CA_COMMON_NAME]
        logger.info("removing CA from Windows Root store")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("Windows CA uninstall failed: %s", exc)
            return False
