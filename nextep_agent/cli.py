"""Local, in-process CLI (no network/websocket).

  status   — print persisted config + each flow's cert state + next renewal
  refresh  — run a config pull + apply now (same path as POST /update)
  install  — install/enable the systemd service and create config dirs
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from cryptography import x509

from nextep_agent.config.models import AgentConfig
from nextep_agent.renewal_timing import compute_next_run
from nextep_agent.settings import Settings


def _load_persisted(path: str) -> AgentConfig | None:
    try:
        with open(path) as fh:
            return AgentConfig.loads(fh.read())
    except FileNotFoundError:
        return None


def _cert_not_after(path: str) -> datetime | None:
    try:
        with open(path, "rb") as fh:
            certs = x509.load_pem_x509_certificates(fh.read())
        return certs[0].not_valid_after_utc if certs else None
    except (FileNotFoundError, ValueError):
        return None


def cmd_status(_args, org) -> int:
    path = org.config_path
    cfg = _load_persisted(path)
    if cfg is None:
        print("not configured (no config file at %s)" % path)
        return 0
    print(f"node: {cfg.node_name}")
    now = datetime.now(timezone.utc)
    for flow in cfg.flows:
        na = _cert_not_after(flow.cert_output_path)
        if na is None:
            state = "no cert on disk"
            nxt = "-"
        else:
            state = f"expires {na.isoformat()}"
            # Best-effort next-run estimate from the on-disk cert.
            nxt = compute_next_run(now, na).isoformat()
        print(f"  [{flow.type}] {flow.cert_output_path}: {state} | next renewal ~ {nxt}")
    return 0


def cmd_refresh(_args, org) -> int:
    settings = Settings.from_env(org)
    if not settings.spog_url:
        print("org config has no spog_url", file=sys.stderr)
        return 2
    from nextep_agent.refresh import RefreshService

    # A one-shot CLI refresh has no long-running scheduler to arm; a no-op stub
    # keeps RefreshService's schedule_flow calls harmless (and avoids pulling in
    # apscheduler for a plain `refresh`).
    class _NoopScheduler:
        def schedule_flow(self, *a, **k) -> None:  # noqa: D401
            pass

    svc = RefreshService(
        spog_url=settings.spog_url,
        machine_cert_path=settings.machine_cert_path,
        machine_key_path=settings.machine_key_path,
        smallstep_root_path=settings.smallstep_root_path,
        scheduler=_NoopScheduler(),
        ca_url=settings.ca_url,
        provisioner=settings.provisioner,
        cert_output_path=settings.cert_output_path,
        key_output_path=settings.key_output_path,
        config_path=settings.config_path,
        acme_admin_email=settings.acme_admin_email,
    )
    try:
        cfg = svc.refresh()
    except Exception as exc:  # noqa: BLE001
        print(f"refresh failed: {exc}", file=sys.stderr)
        return 1
    print(f"refreshed: {len(cfg.flows)} flow(s) applied")
    return 0


_SERVICE_UNIT = """\
[Unit]
Description=nextep certificate agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s serve
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def cmd_install(_args, org) -> int:
    if os.geteuid() != 0:
        print("install must run as root", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(org.config_path), exist_ok=True)
    exe = sys.argv[0]
    unit_path = "/etc/systemd/system/nextep-agent.service"
    with open(unit_path, "w") as fh:
        fh.write(_SERVICE_UNIT % exe)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "nextep-agent"], check=True)
    print(f"installed {unit_path}; start with: systemctl start nextep-agent")
    return 0


def register_subcommands(parser) -> None:
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the agent server").set_defaults(handler=None)
    sub.add_parser("status", help="show config + cert state").set_defaults(
        handler=cmd_status
    )
    sub.add_parser("refresh", help="pull config and apply now").set_defaults(
        handler=cmd_refresh
    )
    sub.add_parser("install", help="install the systemd service").set_defaults(
        handler=cmd_install
    )
