import sys
from pathlib import Path

root_dir = str(Path(__file__).resolve().parents[2])
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from browser_worker.app import is_private_ip, is_url_allowed  # noqa: E402


def test_ssrf_ip_checks():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.1.5") is True
    assert is_private_ip("169.254.169.254") is True
    assert is_private_ip("8.8.8.8") is False

def test_url_ssrf_admission():
    assert is_url_allowed("http://127.0.0.1/admin") is False
    assert is_url_allowed("http://169.254.169.254/latest/meta-data") is False
    assert is_url_allowed("file:///etc/passwd") is False
    assert is_url_allowed("https://example.com/logo.png") is True
