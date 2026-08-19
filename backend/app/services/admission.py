import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class AdmissionError(Exception):
    """Base error raised when a target cannot be safely admitted."""


class SSRFViolationError(AdmissionError):
    """Raised when a hostname resolves to an address that is not public."""


class InvalidURLError(AdmissionError):
    """Raised when a target URL is malformed or uses a forbidden scheme."""


class AdmissionService:
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize a fetchable URL for deterministic deduplication."""
        candidate = url.strip()
        if not candidate:
            raise InvalidURLError("URL must not be empty.")
        if "://" not in candidate:
            candidate = f"http://{candidate}"

        try:
            parsed = urlsplit(candidate)
        except ValueError as exc:
            raise InvalidURLError(f"Malformed URL: {exc}") from exc

        if parsed.scheme.lower() not in {"http", "https"}:
            raise InvalidURLError("Only http and https schemes are permitted.")
        if not parsed.hostname:
            raise InvalidURLError("URL must contain a hostname.")
        if parsed.username or parsed.password:
            raise SSRFViolationError("Credentials in URL are not permitted.")

        try:
            hostname = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise InvalidURLError(f"Invalid hostname or port: {exc}") from exc

        scheme = parsed.scheme.lower()
        netloc = hostname
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{hostname}:{port}"

        path = parsed.path or "/"
        if path != "/":
            had_trailing_slash = path.endswith("/")
            path = path.rstrip("/") or "/"
            if had_trailing_slash:
                path += "/"

        # Query sorting is safe for the crawler's identity because it only affects
        # deduplication; the original URL remains observable in page/link evidence.
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((scheme, netloc, path, query, ""))

    @staticmethod
    def validate_and_resolve(url: str) -> tuple[str, str]:
        """Normalize a URL, resolve all addresses, and reject non-public targets."""
        canonical_url = AdmissionService.normalize_url(url)
        hostname = urlsplit(canonical_url).hostname
        assert hostname is not None

        try:
            addresses = {
                sockaddr[4][0]
                for sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror as exc:
            raise AdmissionError(f"DNS resolution failed for {hostname}") from exc

        if not addresses:
            raise AdmissionError(f"No IP addresses found for {hostname}")

        for resolved_ip in sorted(addresses):
            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
            except ValueError as exc:
                raise AdmissionError(f"Invalid IP address resolved: {resolved_ip}") from exc

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise SSRFViolationError(f"Non-public IP address {resolved_ip} is blocked.")
            if str(ip_obj) == "169.254.169.254":
                raise SSRFViolationError("Cloud metadata IP address is blocked.")

        return canonical_url, sorted(addresses)[0]

    @staticmethod
    def registrable_domain(hostname: str) -> str:
        """Return a conservative two-label registrable-domain approximation."""
        labels = hostname.lower().rstrip(".").split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()

    @staticmethod
    def same_domain(left: str, right: str, mode: str = "hostname") -> bool:
        left_host = (urlsplit(left).hostname or "").lower().rstrip(".")
        right_host = (urlsplit(right).hostname or "").lower().rstrip(".")
        if mode == "registrable":
            return AdmissionService.registrable_domain(
                left_host
            ) == AdmissionService.registrable_domain(right_host)
        return left_host == right_host

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 equivalents
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True

def validate_socket_ip(ip_str: str) -> bool:
    return not is_private_ip(ip_str)

def validate_admission_url(url: str) -> tuple[bool, str]:
    try:
        canonical_url, resolved_ip = AdmissionService.validate_and_resolve(url)
        if is_private_ip(resolved_ip):
            return False, f"Resolved IP {resolved_ip} is in blocked range"
        return True, "Valid admission target"
    except Exception as exc:
        return False, str(exc)

