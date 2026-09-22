"""Renewal scheduling.

The agent is the source of truth for *when* a cert renews. After each successful
issuance we read the new cert's ``not_after`` and schedule the next renewal at a
fraction of the remaining lifetime (renew with a comfortable margin). The
computed next-run is reported to smallhelp for display only.
"""

from __future__ import annotations

from datetime import datetime
from logging import getLogger

from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Re-exported for callers that import from scheduler; the pure timing logic lives
# in renewal_timing so it can be imported/tested without apscheduler present.
from nextep_agent.renewal_timing import (  # noqa: F401
    RENEW_AT_REMAINING_FRACTION,
    compute_next_run,
)

logger = getLogger("scheduler")


class RenewalScheduler:
    """Thin wrapper over APScheduler keyed by a stable per-flow job id."""

    def __init__(self) -> None:
        self._sched = AsyncIOScheduler(timezone="UTC")

    def start(self) -> None:
        self._sched.start()

    def shutdown(self) -> None:
        self._sched.shutdown(wait=False)

    def schedule_flow(self, job_id: str, run_at: datetime, func, *args) -> None:
        """(Re)arm a one-shot renewal job for a flow at ``run_at``."""
        self._sched.add_job(
            func,
            trigger="date",
            run_date=run_at,
            args=args,
            id=job_id,
            replace_existing=True,
            misfire_grace_time=3600,
        )
        logger.info("scheduled %s at %s", job_id, run_at.isoformat())

    def next_run_for(self, job_id: str) -> datetime | None:
        job = self._sched.get_job(job_id)
        return job.next_run_time if job else None
