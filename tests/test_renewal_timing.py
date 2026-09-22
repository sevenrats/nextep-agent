"""Pure renewal-timing math."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from nextep_agent.renewal_timing import (
    RENEW_AT_REMAINING_FRACTION,
    compute_next_run,
)


@pytest.mark.parametrize("days", [90, 30, 15, 1])
def test_renews_at_expected_fraction_of_lifetime(days):
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=days)
    next_run = compute_next_run(now, not_after)

    lifetime = not_after - now
    elapsed_fraction = (next_run - now) / lifetime
    expected = 1.0 - RENEW_AT_REMAINING_FRACTION  # ~0.667
    assert abs(elapsed_fraction - expected) < 0.001


def test_next_run_is_before_expiry():
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=90)
    assert compute_next_run(now, not_after) < not_after


def test_short_lived_cert_clamps_to_near_future():
    now = datetime.now(timezone.utc)
    # A cert expiring in 10s: naive 2/3 point is already past -> clamp forward.
    not_after = now + timedelta(seconds=10)
    next_run = compute_next_run(now, not_after)
    assert next_run > datetime.now(timezone.utc)


def test_already_past_two_thirds_clamps_forward():
    # issued_at far in the past relative to the real clock -> computed point is
    # in the past -> must clamp to the near future, never return a past time.
    issued = datetime(2020, 1, 1, tzinfo=timezone.utc)
    not_after = datetime(2020, 4, 1, tzinfo=timezone.utc)
    next_run = compute_next_run(issued, not_after)
    assert next_run > datetime.now(timezone.utc)
