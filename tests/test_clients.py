"""mTLS config-pull + report clients — via a patched httpx.Client / MockTransport.

The clients build their own httpx.Client, so we patch httpx.Client to (a) capture
the constructor kwargs (asserting the mTLS SSLContext is passed as ``verify``) and
(b) route the request through an httpx.MockTransport we control. The client cert
is loaded eagerly into an ssl.SSLContext at construction, so tests use a real
self-signed cert/key on disk.
"""

from __future__ import annotations

import json
import ssl
from datetime import datetime, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nextep_agent.client.config_client import ConfigClient
from nextep_agent.client.report_client import ReportClient


_REAL_CLIENT = httpx.Client  # captured before any patching


class _Captured:
    kwargs: dict = {}


@pytest.fixture(scope="module")
def creds(tmp_path_factory):
    """A real self-signed cert + key on disk (load_cert_chain needs real files)."""
    d = tmp_path_factory.mktemp("creds")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "m")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "m")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    cert_path = d / "m.pem"
    key_path = d / "m.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _patch_httpx(monkeypatch, module, handler):
    """Replace module.httpx.Client with a factory that records the constructor
    kwargs and routes requests through a MockTransport (built with the *real*
    httpx.Client to avoid recursing into the patch)."""

    def factory(**kwargs):
        _Captured.kwargs = kwargs
        return _REAL_CLIENT(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(module.httpx, "Client", factory)


# --------------------------------------------------------------------------- #
# ConfigClient
# --------------------------------------------------------------------------- #
def test_config_client_pull_success(monkeypatch, creds):
    import nextep_agent.client.config_client as mod

    cert, key = creds
    payload = {"node_name": "host.example.com", "flows": []}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/agent/config"
        assert request.method == "GET"
        return httpx.Response(200, text=json.dumps(payload))

    _patch_httpx(monkeypatch, mod, handler)
    client = ConfigClient(
        spog_url="https://sh.example.com",
        client_cert_path=cert,
        client_key_path=key,
        smallstep_root_path=None,
    )
    cfg = client.pull()
    assert cfg.node_name == "host.example.com"
    # The mTLS credential is carried by the SSLContext passed as verify=.
    assert isinstance(_Captured.kwargs["verify"], ssl.SSLContext)


def test_config_client_404_raises_lookup(monkeypatch, creds):
    import nextep_agent.client.config_client as mod

    cert, key = creds
    _patch_httpx(monkeypatch, mod, lambda r: httpx.Response(404))
    client = ConfigClient(
        spog_url="https://sh",
        client_cert_path=cert,
        client_key_path=key,
    )
    with pytest.raises(LookupError):
        client.pull()


def test_config_client_500_raises(monkeypatch, creds):
    import nextep_agent.client.config_client as mod

    cert, key = creds
    _patch_httpx(monkeypatch, mod, lambda r: httpx.Response(500))
    client = ConfigClient(
        spog_url="https://sh",
        client_cert_path=cert,
        client_key_path=key,
    )
    with pytest.raises(httpx.HTTPStatusError):
        client.pull()


# --------------------------------------------------------------------------- #
# ReportClient
# --------------------------------------------------------------------------- #
def test_report_client_posts_payload(monkeypatch, creds):
    import nextep_agent.client.report_client as mod

    cert, key = creds
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/agent/report"
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    _patch_httpx(monkeypatch, mod, handler)
    na = datetime(2026, 12, 16, tzinfo=timezone.utc)
    nxt = datetime(2026, 10, 16, tzinfo=timezone.utc)
    ReportClient(
        spog_url="https://sh",
        client_cert_path=cert,
        client_key_path=key,
    ).report(
        host="host.example.com",
        flow_type="internal",
        status="renewed",
        not_after=na,
        next_scheduled_run=nxt,
        provider="internal",
        duration=3,
    )
    assert seen["host"] == "host.example.com"
    assert seen["status"] == "renewed"
    assert seen["not_after"] == na.isoformat()
    assert seen["next_scheduled_run"] == nxt.isoformat()
    assert seen["duration"] == 3


def test_report_client_swallows_errors(monkeypatch, creds):
    """Reporting is best-effort telemetry — a transport error must not raise."""
    import nextep_agent.client.report_client as mod

    cert, key = creds

    def handler(request):
        raise httpx.ConnectError("down")

    _patch_httpx(monkeypatch, mod, handler)
    # Should NOT raise despite the connection error.
    ReportClient(
        spog_url="https://sh",
        client_cert_path=cert,
        client_key_path=key,
    ).report(host="h", flow_type="internal", status="failed", error="boom")
