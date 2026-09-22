"""CA certificate trust management — cross-platform.

Ported from the WIP agent's ``x509/ca.py`` with paths rehomed under
``nextep-agent``. Provides the trust-bundle location used to verify smallstep's
server cert (config pull) and the smallstep/step-ca TLS root for the x5c POST,
plus a system-trust installer for bootstrapping a CA root.
"""

from __future__ import annotations

import platform
import socket
import ssl
import subprocess
from pathlib import Path
from urllib.parse import urlparse


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _ca_cert_path() -> Path:
    """Location of the trusted CA bundle (e.g. the smallstep root)."""
    if _is_windows():
        return Path(r"C:\ProgramData\nextep-agent\ca.pem")
    return Path("/etc/nextep-agent/ca.pem")


def is_trusted(directory_url: str) -> bool:
    """Return True if the system trusts the TLS certificate at *directory_url*."""
    parsed = urlparse(directory_url)
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, port)), server_hostname=host
        ) as s:
            s.getpeercert()
        return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        # Connection error, timeout, etc — don't block on this.
        return True


def install(pem: str) -> None:
    """Install a PEM-encoded CA certificate into the system trust store."""
    cert_path = _ca_cert_path()
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_text(pem)

    if _is_windows():
        _install_windows(cert_path)
    else:
        _install_linux(pem)


def _install_linux(pem: str) -> None:
    dest = Path("/usr/local/share/ca-certificates/nextep-agent-ca.crt")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(pem)
    subprocess.run(["update-ca-certificates"], check=True)


def _install_windows(cert_path: Path) -> None:
    subprocess.run(
        ["certutil", "-addstore", "-f", "Root", str(cert_path)],
        check=True,
    )
