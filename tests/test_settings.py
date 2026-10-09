"""Bootstrap settings: org-level values from the org config, env only for the
per-deployment nudge secret + listener bind."""

from __future__ import annotations

import os

from nextep_agent.org import AbstractOrganizationConfig
from nextep_agent.settings import Settings


class _FakeOrg(AbstractOrganizationConfig):
    spog_url = "https://sh.example.edu"
    ca_url = "https://ca.example.edu:444"
    provisioner = "example-x5c"
    smallstep_root_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
    machine_cert_path = "/org/machine.pem"
    machine_key_path = "/org/machine.key"
    config_path = "/org/config.json"
    acme_admin_email = "certs@example.com"


def _clear_nextep_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("NEXTEP_"):
            monkeypatch.delenv(k, raising=False)


def test_org_values_sourced_from_org_config(monkeypatch):
    _clear_nextep_env(monkeypatch)
    s = Settings.from_env(_FakeOrg())
    assert s.spog_url == "https://sh.example.edu"
    assert s.ca_url == "https://ca.example.edu:444"
    assert s.provisioner == "example-x5c"
    assert s.machine_cert_path == "/org/machine.pem"
    assert s.machine_key_path == "/org/machine.key"
    assert "BEGIN CERTIFICATE" in s.smallstep_root_pem


def test_deployment_values_from_env(monkeypatch):
    _clear_nextep_env(monkeypatch)
    s = Settings.from_env(_FakeOrg())
    assert s.nudge_secret == b""
    assert s.bind_port == 9999

    monkeypatch.setenv("NEXTEP_NUDGE_SECRET", "sekret")
    monkeypatch.setenv("NEXTEP_BIND_PORT", "8443")
    s = Settings.from_env(_FakeOrg())
    assert s.nudge_secret == b"sekret"
    assert s.bind_port == 8443
