"""OS-family detection for the machine credential paths certmonger writes.

The AD machine cert/key (certmonger's enrollment output, presented as the x5c /
mTLS credential) lands at a conventional location that differs by OS family:

  * Debian/Ubuntu : /etc/ssl/certs/machine.pem   + /etc/ssl/private/machine.key
  * RHEL/OL/Fedora: /etc/pki/tls/certs/machine.pem + /etc/pki/tls/private/machine.key

These mirror the paths the companion enroll-machine-cert.sh writes per OS, so the
agent reads whatever realmd/certmonger put down without any per-host config. The
family is read from /etc/os-release ID/ID_LIKE (same signal the enroll script
uses); anything unrecognised falls back to the Debian layout, which is the widest
convention and matches the project's original default.
"""

from __future__ import annotations

import platform

# Conventional certmonger machine-cert output paths, by OS family.
_DEBIAN_CERT = "/etc/ssl/certs/machine.pem"
_DEBIAN_KEY = "/etc/ssl/private/machine.key"
_RHEL_CERT = "/etc/pki/tls/certs/machine.pem"
_RHEL_KEY = "/etc/pki/tls/private/machine.key"


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


def machine_cert_path(os_release_path: str = "/etc/os-release") -> str:
    """Conventional machine cert path for this OS (Debian layout if unknown)."""
    return _RHEL_CERT if _os_family(os_release_path) == "rhel" else _DEBIAN_CERT


def machine_key_path(os_release_path: str = "/etc/os-release") -> str:
    """Conventional machine key path for this OS (Debian layout if unknown)."""
    return _RHEL_KEY if _os_family(os_release_path) == "rhel" else _DEBIAN_KEY
