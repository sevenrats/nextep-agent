"""OS-family detection for the conventional TLS cert/key directories.

TLS material lives under a different tree by OS family:

  * Debian/Ubuntu : /etc/ssl/certs       + /etc/ssl/private
  * RHEL/OL/Fedora: /etc/pki/tls/certs   + /etc/pki/tls/private

The agent is the only component that knows the node's OS (the SPOG serves many
hosts and cannot), so OS-dependent paths are resolved here, not server-side:

  * the AD machine cert/key certmonger writes (the x5c / mTLS credential the agent
    READS), via machine_cert_path/machine_key_path; and
  * the per-flow output directory an issued cert is WRITTEN to when the pulled
    config leaves it blank, via cert_output_dir/key_output_dir.

Family is read from /etc/os-release ID/ID_LIKE (the same signal the companion
enroll-machine-cert.sh keys on); anything unrecognised falls back to the Debian
layout, the widest convention and the project's original default.
"""

from __future__ import annotations

import platform

# Conventional TLS directories, by OS family.
_DEBIAN_CERT_DIR = "/etc/ssl/certs"
_DEBIAN_KEY_DIR = "/etc/ssl/private"
_RHEL_CERT_DIR = "/etc/pki/tls/certs"
_RHEL_KEY_DIR = "/etc/pki/tls/private"


def _os_family(os_release_path: str = "/etc/os-release") -> str:
    """Return "rhel", "debian", or "" (unknown) from /etc/os-release.

    Matches ID / ID_LIKE against the same families the enroll script keys on.
    Never raises: an unreadable or absent file yields "" (caller defaults).
    """
    if platform.system() != "Linux":
        return ""
    ids: list[str] = []
    try:
        with open(os_release_path) as fh:
            for line in fh:
                key, _, val = line.partition("=")
                if key in ("ID", "ID_LIKE"):
                    ids.extend(val.strip().strip('"').split())
    except OSError:
        return ""
    tokens = set(ids)
    if tokens & {"rhel", "fedora", "ol", "centos"}:
        return "rhel"
    if tokens & {"debian", "ubuntu"}:
        return "debian"
    return ""


def cert_output_dir(os_release_path: str = "/etc/os-release") -> str:
    """Conventional cert directory for this OS (Debian layout if unknown)."""
    return _RHEL_CERT_DIR if _os_family(os_release_path) == "rhel" else _DEBIAN_CERT_DIR


def key_output_dir(os_release_path: str = "/etc/os-release") -> str:
    """Conventional private-key directory for this OS (Debian layout if unknown)."""
    return _RHEL_KEY_DIR if _os_family(os_release_path) == "rhel" else _DEBIAN_KEY_DIR


def machine_cert_path(os_release_path: str = "/etc/os-release") -> str:
    """Conventional machine cert path for this OS (Debian layout if unknown)."""
    return f"{cert_output_dir(os_release_path)}/machine.pem"


def machine_key_path(os_release_path: str = "/etc/os-release") -> str:
    """Conventional machine key path for this OS (Debian layout if unknown)."""
    return f"{key_output_dir(os_release_path)}/machine.key"
