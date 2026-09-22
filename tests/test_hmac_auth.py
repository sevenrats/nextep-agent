"""Wake-up nudge HMAC verification — must match smallhelp's RemoteUpdateService."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from nextep_agent.server.hmac_auth import verify_nudge

SECRET = b"shared-remote-update-secret"


def _sign(secret: bytes, ts: int, nonce: str, msg: str) -> str:
    """Reproduce smallhelp status/remote_update.py signing exactly."""
    canonical = f"v1|{ts}|{nonce}|{msg}".encode()
    mac = hmac.new(secret, canonical, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def _valid(**over):
    ts = over.get("ts", int(time.time()))
    nonce = over.get("nonce", "a1b2c3d4" * 4)
    msg = over.get("msg", "host0.example.org")
    secret = over.get("secret", SECRET)
    sig = over.get("sig", _sign(secret, ts, nonce, msg))
    return dict(ts=ts, nonce=nonce, msg=msg, sig=sig)


def test_valid_nudge_accepted():
    v = _valid()
    assert verify_nudge(
        SECRET,
        ts_header=str(v["ts"]),
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body=v["msg"],
    )


def test_tampered_body_rejected():
    v = _valid()
    assert not verify_nudge(
        SECRET,
        ts_header=str(v["ts"]),
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body="evil.host",  # signature was for host0
    )


def test_stale_timestamp_rejected():
    v = _valid(ts=int(time.time()) - 10_000)
    assert not verify_nudge(
        SECRET,
        ts_header=str(v["ts"]),
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body=v["msg"],
    )


def test_wrong_secret_rejected():
    v = _valid()
    assert not verify_nudge(
        b"different-secret",
        ts_header=str(v["ts"]),
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body=v["msg"],
    )


def test_missing_headers_rejected():
    assert not verify_nudge(SECRET, ts_header="", nonce_header="", sig_header="", body="x")


def test_non_integer_ts_rejected():
    v = _valid()
    assert not verify_nudge(
        SECRET,
        ts_header="not-a-number",
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body=v["msg"],
    )


def test_empty_secret_rejected():
    v = _valid()
    assert not verify_nudge(
        b"",
        ts_header=str(v["ts"]),
        nonce_header=v["nonce"],
        sig_header=v["sig"],
        body=v["msg"],
    )
