import pytest
from datetime import datetime, timedelta, UTC
from app.models.scan import Scan
from app.services.tasks import check_scan_wall_clock_timeout

def test_scan_wall_clock_timeout():
    old_scan = Scan(
        requested_url="https://example.com",
        state="COLLECTING",
        created_at=datetime.now(UTC) - timedelta(seconds=700)
    )
    is_timed_out = check_scan_wall_clock_timeout(old_scan, timeout_seconds=600)
    assert is_timed_out is True
    assert old_scan.state == "PARTIAL_FAILED"

def test_scan_within_time_limit():
    recent_scan = Scan(
        requested_url="https://example.com",
        state="COLLECTING",
        created_at=datetime.now(UTC) - timedelta(seconds=100)
    )
    is_timed_out = check_scan_wall_clock_timeout(recent_scan, timeout_seconds=600)
    assert is_timed_out is False
    assert recent_scan.state == "COLLECTING"
