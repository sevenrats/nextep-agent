"""Agent HTTP surface — via FastAPI TestClient (in-memory, no network)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nextep_agent.server.router import router

SECRET = b"nudge-secret"


def _sign(ts: int, nonce: str, msg: str, secret: bytes = SECRET) -> str:
    canonical = f"v1|{ts}|{nonce}|{msg}".encode()
    return base64.urlsafe_b64encode(
        hmac.new(secret, canonical, hashlib.sha256).digest()
    ).decode().rstrip("=")


class _FakeRefresh:
    def __init__(self, cfg=None):
        self.config = cfg
        self.next_runs = {}
        self.calls = 0
        self._event = threading.Event()

    def refresh(self):
        self.calls += 1
        self._event.set()

    def wait(self, timeout=2.0):
        return self._event.wait(timeout)


@pytest.fixture
def client_and_refresh():
    app = FastAPI()
    app.include_router(router)
    refresh = _FakeRefresh()
    app.state.refresh = refresh
    app.state.nudge_secret = SECRET
    with TestClient(app) as client:
        yield client, refresh


def test_healthz(client_and_refresh):
    client, _ = client_and_refresh
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_update_accepts_valid_signature(client_and_refresh):
    client, refresh = client_and_refresh
    ts, nonce, body = int(time.time()), "n0nc3", "host.example.com"
    resp = client.post(
        "/update",
        content=body,
        headers={"X-Ts": str(ts), "X-Nonce": nonce, "X-Sig": _sign(ts, nonce, body)},
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] is True
    # refresh dispatched to the executor — wait for it to run
    assert refresh.wait()
    assert refresh.calls == 1


def test_update_rejects_bad_signature(client_and_refresh):
    client, refresh = client_and_refresh
    ts, nonce, body = int(time.time()), "n0nc3", "host.example.com"
    resp = client.post(
        "/update",
        content=body,
        headers={"X-Ts": str(ts), "X-Nonce": nonce, "X-Sig": "wrong"},
    )
    assert resp.status_code == 401
    assert refresh.calls == 0


def test_update_rejects_wrong_body(client_and_refresh):
    client, refresh = client_and_refresh
    ts, nonce = int(time.time()), "n0nc3"
    sig = _sign(ts, nonce, "host.example.com")  # signed for a different body
    resp = client.post(
        "/update",
        content="evil.host",
        headers={"X-Ts": str(ts), "X-Nonce": nonce, "X-Sig": sig},
    )
    assert resp.status_code == 401
    assert refresh.calls == 0


def test_status_unconfigured(client_and_refresh):
    client, _ = client_and_refresh
    resp = client.get("/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["flows"] == []
    assert body["node_name"] is None


def test_status_reports_flows_and_next_run():
    import json

    from nextep_agent.config.models import AgentConfig

    cfg = AgentConfig.loads(
        json.dumps(
            {
                "node_name": "host.example.com",
                "flows": [
                    {
                        "type": "internal",
                        "cert_output_path": "/c0",
                        "key_output_path": "/k0",
                        "config": {"provisioner": "p", "hostname": "h"},
                    }
                ],
            }
        )
    )
    app = FastAPI()
    app.include_router(router)
    refresh = _FakeRefresh(cfg)
    nxt = datetime(2026, 12, 1, tzinfo=timezone.utc)
    refresh.next_runs = {"renew:internal:0": nxt}
    app.state.refresh = refresh
    app.state.nudge_secret = SECRET
    with TestClient(app) as client:
        body = client.get("/status").json()
    assert body["configured"] is True
    assert body["node_name"] == "host.example.com"
    assert body["flows"][0]["type"] == "internal"
    assert body["flows"][0]["cert_output_path"] == "/c0"
    assert body["flows"][0]["next_scheduled_run"] == nxt.isoformat()
