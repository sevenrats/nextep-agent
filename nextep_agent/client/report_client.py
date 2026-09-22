"""mTLS renewal/issue-event reporter (agent -> smallhelp).

After each flow issuance the agent reports the outcome — including the
agent-computed ``next_scheduled_run`` — so the SPOG can DISPLAY expected
renewals. smallhelp is not the source of truth for renewal timing; the agent is.
"""

from __future__ import annotations

from datetime import datetime
from logging import getLogger

import httpx

from nextep_agent.client.mtls import build_mtls_context


class ReportClient:
    def __init__(
        self,
        *,
        spog_url: str,
        client_cert_path: str,
        client_key_path: str,
        smallstep_root_path: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.logger = getLogger("report")
        self._url = f"{spog_url.rstrip('/')}/agent/report"
        self._ctx = build_mtls_context(
            client_cert_path, client_key_path, smallstep_root_path
        )
        self._timeout = timeout

    def report(
        self,
        *,
        host: str,
        flow_type: str,
        status: str,
        not_after: datetime | None = None,
        next_scheduled_run: datetime | None = None,
        provider: str | None = None,
        duration: int | None = None,
        error: str | None = None,
    ) -> None:
        payload = {
            "host": host,
            "flow_type": flow_type,
            "status": status,  # issued | renewed | failed
            "not_after": not_after.isoformat() if not_after else None,
            "next_scheduled_run": (
                next_scheduled_run.isoformat() if next_scheduled_run else None
            ),
            "provider": provider,
            "duration": duration,
            "error": error,
        }
        try:
            with httpx.Client(
                verify=self._ctx, timeout=self._timeout
            ) as client:
                resp = client.post(self._url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            # Reporting is best-effort telemetry; never fail issuance over it.
            self.logger.warning("failed to report %s event: %s", flow_type, exc)
