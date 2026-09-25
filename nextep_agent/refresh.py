"""RefreshService — the core loop shared by /update, CLI refresh, and renewals.

A refresh: pull the AgentConfig from smallhelp over mTLS, run every configured
flow (issue -> write -> post-renewal hook), report each outcome + computed
next-run to smallhelp, and (re)arm per-flow renewal jobs. Individual flow
failures are isolated so one bad flow does not sink the others.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from logging import getLogger
from typing import TYPE_CHECKING

from nextep_agent.client.config_client import ConfigClient
from nextep_agent.client.report_client import ReportClient
from nextep_agent.config.models import AgentConfig
from nextep_agent.config.models import config_path as config_path_default
from nextep_agent.flows import make_runner
from nextep_agent.flows.base import BootstrapDefaults
from nextep_agent.renewal_timing import compute_next_run

if TYPE_CHECKING:
    # Type-only: importing the real scheduler drags apscheduler, which the CLI
    # `refresh` path (which passes a no-op scheduler stub) should not require.
    from nextep_agent.scheduler import RenewalScheduler


def _flow_job_id(flow_type: str, index: int) -> str:
    return f"renew:{flow_type}:{index}"


class RefreshService:
    def __init__(
        self,
        *,
        spog_url: str,
        machine_cert_path: str,
        machine_key_path: str,
        smallstep_root_path: str | None,
        scheduler: RenewalScheduler,
        ca_url: str = "",
        provisioner: str = "",
        cert_output_path: str = "",
        key_output_path: str = "",
        config_path: str = "",
        acme_admin_email: str = "",
    ) -> None:
        self.logger = getLogger("refresh")
        self._spog_url = spog_url
        self._cert = machine_cert_path
        self._key = machine_key_path
        self._root = smallstep_root_path
        self._ca_url = ca_url
        self._provisioner = provisioner
        self._cert_output_path = cert_output_path
        self._key_output_path = key_output_path
        self._config_path = config_path or config_path_default()
        self._acme_admin_email = acme_admin_email
        self._scheduler = scheduler
        self._config: AgentConfig | None = None
        #: last computed next-run per job id, for local status display
        self.next_runs: dict[str, datetime] = {}

    @property
    def config(self) -> AgentConfig | None:
        return self._config

    def _config_client(self) -> ConfigClient:
        return ConfigClient(
            spog_url=self._spog_url,
            client_cert_path=self._cert,
            client_key_path=self._key,
            smallstep_root_path=self._root,
        )

    def _report_client(self) -> ReportClient:
        return ReportClient(
            spog_url=self._spog_url,
            client_cert_path=self._cert,
            client_key_path=self._key,
            smallstep_root_path=self._root,
        )

    def _bootstrap_defaults(self) -> BootstrapDefaults:
        """Agent-local fallbacks for flows: the smallstep root (same one used for
        the config-pull mTLS verify) + the OS-fixed machine cert/key paths."""
        return BootstrapDefaults(
            smallstep_root_path=self._root,
            machine_cert_path=self._cert,
            machine_key_path=self._key,
            ca_url=self._ca_url,
            provisioner=self._provisioner,
            cert_output_path=self._cert_output_path,
            key_output_path=self._key_output_path,
            acme_admin_email=self._acme_admin_email,
        )

    # -- top-level refresh ----------------------------------------------------
    def refresh(self) -> AgentConfig:
        """Pull config and run every flow. Returns the pulled config."""
        cfg = self._config_client().pull()
        self._config = cfg
        try:
            cfg_str = AgentConfig.dumps(cfg)
            path = self._config_path
            import os

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(cfg_str)
            os.chmod(path, 0o600)
        except OSError as exc:
            self.logger.warning("could not persist config: %s", exc)

        for index, flow in enumerate(cfg.flows):
            self._run_one_flow(cfg, index, flow)
        return cfg

    def renew_one(self, index: int) -> None:
        """Scheduler entry point: re-run a single flow by index against the
        currently-held config (falls back to a full refresh if none held)."""
        cfg = self._config
        if cfg is None or index >= len(cfg.flows):
            self.refresh()
            return
        self._run_one_flow(cfg, index, cfg.flows[index])

    # -- single flow ----------------------------------------------------------
    def _run_one_flow(self, cfg: AgentConfig, index: int, flow) -> None:
        host = cfg.node_name
        job_id = _flow_job_id(str(flow.type), index)
        started = time.monotonic()
        try:
            runner = make_runner(flow, cfg.org, self._bootstrap_defaults())
            result = runner.run()
        except Exception as exc:  # isolate per-flow failure
            self.logger.error("flow %s failed: %s", flow.type, exc)
            self._report_client().report(
                host=host,
                flow_type=str(flow.type),
                status="failed",
                error=str(exc),
            )
            return

        duration = int(time.monotonic() - started)
        issued_at = datetime.now(timezone.utc)
        next_run = compute_next_run(issued_at, result.not_after)
        self.next_runs[job_id] = next_run

        # (Re)arm the renewal job for this flow.
        self._scheduler.schedule_flow(job_id, next_run, self.renew_one, index)

        self._report_client().report(
            host=host,
            flow_type=str(flow.type),
            status="renewed" if result.changed else "issued",
            not_after=result.not_after,
            next_scheduled_run=next_run,
            provider=str(flow.type),
            duration=duration,
        )
        self.logger.info(
            "flow %s ok — not_after=%s next_run=%s",
            flow.type,
            result.not_after.isoformat(),
            next_run.isoformat(),
        )
