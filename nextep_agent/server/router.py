"""The agent's own HTTP surface.

  POST /update   — HMAC-verified wake-up nudge from smallhelp; triggers a full
                   config pull + flow (re)issue.
  GET  /healthz  — liveness.
  GET  /status   — local status: config summary + per-flow next scheduled run.
"""

from __future__ import annotations

import asyncio
from logging import getLogger

from fastapi import APIRouter, HTTPException, Request

from nextep_agent.server.hmac_auth import verify_nudge

logger = getLogger("server")

router = APIRouter()


@router.get("/healthz")
async def healthz():
    return {"ok": True}


@router.post("/update")
async def update(request: Request):
    secret: bytes = request.app.state.nudge_secret
    raw = (await request.body()).decode("utf-8", "replace")
    ok = verify_nudge(
        secret,
        ts_header=request.headers.get("X-Ts", ""),
        nonce_header=request.headers.get("X-Nonce", ""),
        sig_header=request.headers.get("X-Sig", ""),
        body=raw,
    )
    if not ok:
        logger.info("nudge rejected: bad signature")
        raise HTTPException(status_code=401, detail="invalid signature")

    # Run the (blocking) refresh off the event loop so we return promptly.
    refresh = request.app.state.refresh
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, refresh.refresh)
    logger.info("nudge accepted: refresh dispatched")
    return {"ok": True, "accepted": True}


@router.get("/status")
async def status(request: Request):
    refresh = request.app.state.refresh
    cfg = refresh.config
    flows = []
    if cfg is not None:
        for index, flow in enumerate(cfg.flows):
            job_id = f"renew:{flow.type}:{index}"
            nxt = refresh.next_runs.get(job_id)
            flows.append(
                {
                    "type": str(flow.type),
                    "cert_output_path": flow.cert_output_path,
                    "next_scheduled_run": nxt.isoformat() if nxt else None,
                }
            )
    return {
        "node_name": cfg.node_name if cfg else None,
        "configured": cfg is not None,
        "flows": flows,
    }
