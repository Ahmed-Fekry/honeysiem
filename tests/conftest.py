from datetime import datetime, timedelta, timezone

import pytest

from honeysiem.models import Event

T0 = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def ev(event_type, seconds=0, ip="203.0.113.10", **kw):
    return Event(timestamp=T0 + timedelta(seconds=seconds), src_ip=ip, event_type=event_type, **kw)


@pytest.fixture
def make_event():
    return ev
