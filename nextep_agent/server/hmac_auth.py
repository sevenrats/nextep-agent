"""Verify the smallhelp wake-up nudge HMAC.

Mirrors smallhelp's ``status/remote_update.py`` RemoteUpdateService signing:
canonical string ``v1|<ts>|<nonce>|<msg>`` HMAC-SHA256'd with the shared secret,
base64url (no padding) in the ``X-Sig`` header, alongside ``X-Ts`` / ``X-Nonce``.
``<msg>`` is the request body (the hostname).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign(secret: bytes, ts: int, nonce_hex: str, msg: str) -> str:
    canonical = f"v1|{ts}|{nonce_hex}|{msg}".encode("utf-8")
    return _b64url_no_pad(hmac.new(secret, canonical, hashlib.sha256).digest())


def verify_nudge(
    secret: bytes,
    *,
    ts_header: str,
    nonce_header: str,
    sig_header: str,
    body: str,
    max_skew_seconds: int = 300,
) -> bool:
    """Constant-time verify the nudge signature, with a freshness window."""
    if not (secret and ts_header and nonce_header and sig_header):
        return False
    try:
        ts = int(ts_header)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    expected = _sign(secret, ts, nonce_header, body)
    return hmac.compare_digest(expected, sig_header)
