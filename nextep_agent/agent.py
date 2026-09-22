"""nextep-agent runner — FastAPI server + local CLI, dispatched by :func:`run`.

A consumer fork supplies its concrete :class:`AbstractOrganizationConfig` and
calls :func:`run` (see kvcc-nextep-agent); this package ships no org and no
console script of its own.

`serve` runs the agent's own HTTP server (the /update nudge endpoint + status),
starts the renewal scheduler, and does an initial config pull. All other CLI
subcommands run in-process (see :mod:`nextep_agent.cli`).
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from nextep_agent.base.startup import Startup
from nextep_agent.cli import register_subcommands
from nextep_agent.logger import configure_logging
from nextep_agent.org import AbstractOrganizationConfig
from nextep_agent.refresh import RefreshService
from nextep_agent.scheduler import RenewalScheduler
from nextep_agent.server.router import router
from nextep_agent.settings import Settings

configure_logging(
    log_file=None,
    loggers={"apscheduler": {"level": "WRN"}, "httpx": {"level": "WRN"}},
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger = logging.getLogger("lifespan")
    settings: Settings = app.state.settings

    scheduler = RenewalScheduler()
    scheduler.start()
    refresh = RefreshService(
        spog_url=settings.spog_url,
        machine_cert_path=settings.machine_cert_path,
        machine_key_path=settings.machine_key_path,
        smallstep_root_path=settings.smallstep_root_path,
        scheduler=scheduler,
        ca_url=settings.ca_url,
        provisioner=settings.provisioner,
        cert_output_path=settings.cert_output_path,
        key_output_path=settings.key_output_path,
    )
    app.state.scheduler = scheduler
    app.state.refresh = refresh
    app.state.nudge_secret = settings.nudge_secret

    # Initial pull on boot — best-effort; the /update nudge will retry.
    # refresh() is blocking (httpx + issuance), so run it off the event loop so
    # startup doesn't stall the server (same reason /update dispatches to a thread).
    async def _initial_refresh() -> None:
        try:
            await asyncio.to_thread(refresh.refresh)
        except Exception as exc:  # noqa: BLE001
            logger.warning("initial refresh failed (will retry on nudge): %s", exc)

    asyncio.create_task(_initial_refresh())

    yield
    scheduler.shutdown()


def _build_app(settings: Settings) -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.state.settings = settings
    app.include_router(router)
    return app


def _serve(org: AbstractOrganizationConfig) -> int:
    settings = Settings.from_env(org)
    app = _build_app(settings)
    uvicorn.run(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        log_level="warning",
    )
    return 0


def run(org: AbstractOrganizationConfig, argv: list[str] | None = None) -> int:
    """Public consumer entrypoint: parse argv and dispatch, using ``org`` for all
    org-level config. This package ships no org, so a consumer fork supplies its
    concrete :class:`AbstractOrganizationConfig` here (see kvcc-nextep-agent)."""
    parser = Startup.init_arg_parser()
    register_subcommands(parser)
    args = parser.parse_args(argv)

    command = getattr(args, "command", None)
    if command in (None, "serve"):
        return _serve(org)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args, org)
