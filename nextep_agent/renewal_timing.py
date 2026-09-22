"""Pure renewal-timing math (no scheduler dependency, so it is trivially testable).

The agent is the source of truth for *when* a cert renews: it reads the issued
cert's lifetime and renews once ``RENEW_AT_REMAINING_FRACTION`` of that lifetime
remains, clamped to never land in the past.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

#: Renew once this fraction of the certificate's lifetime remains. 1/3 remaining
#: == renew at ~2/3 through the validity window.
RENEW_AT_REMAINING_FRACTION = 1.0 / 3.0


def compute_next_run(issued_at: datetime, not_after: datetime) -> datetime:
    """When to renew, leaving RENEW_AT_REMAINING_FRACTION of the lifetime as margin.

    Clamped to never be in the past (short-lived certs -> renew ~now).
    """
    lifetime = not_after - issued_at
    margin = lifetime * RENEW_AT_REMAINING_FRACTION
    next_run = not_after - margin
    now = datetime.now(timezone.utc)
    if next_run <= now:
        return now + timedelta(seconds=30)
    return next_run
