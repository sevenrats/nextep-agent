"""Agent bootstrap settings.

Org-level constants (SPOG URL, CA + provisioner, trust bundle, machine credential
and output paths) come from the :class:`AbstractOrganizationConfig` a consumer
supplies — they are identical across every node and are never sourced from env.
Only the genuinely per-deployment bits live in env: the nudge HMAC secret (a
secret, must not be baked in) and the local listener bind. The pulled
AgentConfig carries everything per-host/per-flow.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from nextep_agent.org import AbstractOrganizationConfig

DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 9999


@dataclass
class Settings:
    spog_url: str
    machine_cert_path: str
    machine_key_path: str
    smallstep_root_path: str | None
    nudge_secret: bytes
    bind_host: str
    bind_port: int
    ca_url: str
    provisioner: str
    cert_output_path: str
    key_output_path: str

    @classmethod
    def from_env(cls, org: AbstractOrganizationConfig) -> "Settings":
        root = org.smallstep_root_path
        # Only pass a bundle path if it exists; else fall back to system trust.
        root_path = root if root and os.path.exists(root) else None
        secret = os.environ.get("NEXTEP_NUDGE_SECRET", "").encode("utf-8")
        return cls(
            spog_url=org.spog_url,
            machine_cert_path=org.machine_cert_path,
            machine_key_path=org.machine_key_path,
            smallstep_root_path=root_path,
            nudge_secret=secret,
            bind_host=os.environ.get("NEXTEP_BIND_HOST", DEFAULT_BIND_HOST),
            bind_port=int(os.environ.get("NEXTEP_BIND_PORT", DEFAULT_BIND_PORT)),
            ca_url=org.ca_url,
            provisioner=org.provisioner,
            cert_output_path=org.cert_output_path,
            key_output_path=org.key_output_path,
        )
