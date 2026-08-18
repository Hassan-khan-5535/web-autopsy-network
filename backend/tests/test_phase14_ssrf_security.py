import pytest
from app.services.admission import (
    AdmissionService,
    SSRFViolationError,
    is_private_ip,
    validate_socket_ip,
    validate_admission_url,
)

def test_private_ip_detection():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.1.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("169.254.169.254") is True
    assert is_private_ip("::1") is True
    assert is_private_ip("fe80::1") is True
    assert is_private_ip("fc00::1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False

def test_validate_socket_ip():
    assert validate_socket_ip("127.0.0.1") is False
    assert validate_socket_ip("93.184.216.34") is True

def test_validate_admission_url_blocked():
    valid, reason = validate_admission_url("http://127.0.0.1/admin")
    assert valid is False
    assert "blocked" in reason.lower() or "ssrf" in reason.lower() or "private" in reason.lower()

def test_validate_admission_url_cloud_metadata():
    valid, reason = validate_admission_url("http://169.254.169.254/latest/meta-data/")
    assert valid is False

def test_validate_admission_url_valid():
    valid, reason = validate_admission_url("https://example.com")
    assert valid is True

def test_browser_client_ssrf_precheck():
    from app.services.browser_client import BrowserWorkerClient
    from unittest.mock import MagicMock
    db = MagicMock()
    client = BrowserWorkerClient(db)
    result = client.analyze_page("00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000", "http://169.254.169.254/latest/meta-data/")
    assert result is False

