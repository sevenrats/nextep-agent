"""RenewalScheduler slot decoding (the daily cron path)."""

from __future__ import annotations

import pytest

from nextep_agent.scheduler import RenewalScheduler


@pytest.fixture
def sched():
    # No start(): add_job works on a non-running scheduler, and inspecting the
    # job's trigger needs no event loop (start() would require one).
    return RenewalScheduler()


def _cron_hm(job):
    """Extract (hour, minute) integers from a job's CronTrigger fields."""
    fields = {f.name: str(f) for f in job.trigger.fields}
    return int(fields["hour"]), int(fields["minute"])


@pytest.mark.parametrize(
    "slot,expected",
    [
        (0, (0, 0)),
        (6, (1, 0)),        # 6 * 10 = 60 min = 01:00
        (60, (10, 0)),      # 600 min = 10:00
        (61, (10, 10)),
        (143, (23, 50)),    # last slot of the day
    ],
)
def test_daily_slot_decodes_to_cron_hour_minute(sched, slot, expected):
    sched.schedule_flow_daily("job:x", slot, lambda: None)
    job = sched._sched.get_job("job:x")
    assert _cron_hm(job) == expected


def test_daily_replaces_existing():
    # replace_existing takes effect on a running scheduler (needs an event loop),
    # so drive it inside asyncio.run rather than requiring pytest-asyncio.
    import asyncio

    async def _run():
        s = RenewalScheduler()
        s.start()
        try:
            s.schedule_flow_daily("job:x", 0, lambda: None)
            s.schedule_flow_daily("job:x", 143, lambda: None)
            return _cron_hm(s._sched.get_job("job:x"))
        finally:
            s.shutdown()

    assert asyncio.run(_run()) == (23, 50)
