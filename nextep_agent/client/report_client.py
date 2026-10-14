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
        ca_pem: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.logger = getLogger("report")
        self._url = f"{spog_url.rstrip('/')}/agent/report"
        self._ctx = build_mtls_context(client_cert_path, client_key_path, ca_pem)
        self._timeout = timeout

    def report(
        self,
        *,
        host: str,
        flow_type: str,
        status: str,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        next_scheduled_run: datetime | None = None,
        provider: str | None = None,
        error: str | None = None,
    ) -> None:
        # Report the issued cert's validity window (not_before/not_after); smallhelp
        # derives the "duration (days)" column from these. We deliberately do NOT
        # send a precomputed duration: it previously carried the issuance ELAPSED
        # time (a stopwatch), which the server stored as the cert lifetime and
        # displayed as "0 days". Duration is a property of the cert, computed once,
        # server-side, from its own dates.
        payload = {
            "host": host,
            "flow_type": flow_type,
            "status": status,  # issued | renewed | failed
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "next_scheduled_run": (
                next_scheduled_run.isoformat() if next_scheduled_run else None
            ),
            "provider": provider,
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
