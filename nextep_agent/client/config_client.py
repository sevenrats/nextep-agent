"""mTLS config-pull client (agent -> smallhelp).

The agent presents its AD machine cert (machine.pem + key) as the client cert;
smallhelp keys the lookup on the cert's Subject CN (== Host.common_name) and
returns this host's ``AgentConfig``. smallhelp presents a server cert chaining
to the smallstep root, which we verify against ``smallstep_root_path``.
"""

from __future__ import annotations

from logging import getLogger

import httpx

from nextep_agent.config.models import AgentConfig
from nextep_agent.client.mtls import build_mtls_context


class ConfigClient:
    def __init__(
        self,
        *,
        spog_url: str,
        client_cert_path: str,
        client_key_path: str,
        smallstep_root_path: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.logger = getLogger("config")
        self._url = f"{spog_url.rstrip('/')}/agent/config"
        self._ctx = build_mtls_context(
            client_cert_path, client_key_path, smallstep_root_path
        )
        self._timeout = timeout

    def pull(self) -> AgentConfig:
        """Fetch and parse this host's AgentConfig over mTLS."""
        self.logger.info("Pulling config from %s", self._url)
        with httpx.Client(verify=self._ctx, timeout=self._timeout) as client:
            resp = client.get(self._url)
        if resp.status_code == 404:
            raise LookupError("smallhelp does not know this host (404)")
        resp.raise_for_status()
        return AgentConfig.loads(resp.text)
