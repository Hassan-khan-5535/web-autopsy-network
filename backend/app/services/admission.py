import ipaddress
import socket
from urllib.parse import urlparse

class AdmissionError(Exception):
    pass

class SSARFViolationError(AdmissionError):
    pass

class InvalidURLError(AdmissionError):
    pass

class AdmissionService:
    @staticmethod
    def validate_and_resolve(url: str) -> tuple[str, str]:
        """
        Validates the URL and resolves its DNS, checking for SSRF violations.
        Returns a tuple of (canonical_url, resolved_ip).
        """
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise InvalidURLError(f"Malformed URL: {e}")

        if parsed.scheme not in ("http", "https"):
            raise InvalidURLError("Only http and https schemes are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise InvalidURLError("URL must contain a hostname.")

        # Check for userinfo (credentials in URL)
        if parsed.username or parsed.password:
            raise SSARFViolationError("Credentials in URL are not permitted.")

        try:
            # Resolve DNS
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            _, _, ip_addresses = socket.gethostbyname_ex(hostname)
        except socket.gaierror:
            raise AdmissionError(f"DNS resolution failed for {hostname}")

        if not ip_addresses:
            raise AdmissionError(f"No IP addresses found for {hostname}")

        resolved_ip = ip_addresses[0]

        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
        except ValueError:
            raise AdmissionError(f"Invalid IP address resolved: {resolved_ip}")

        # SSRF Checks
        if ip_obj.is_private:
            raise SSARFViolationError(f"Private IP address {resolved_ip} is blocked.")
        if ip_obj.is_loopback:
            raise SSARFViolationError(f"Loopback IP address {resolved_ip} is blocked.")
        if ip_obj.is_link_local:
            raise SSARFViolationError(f"Link-local IP address {resolved_ip} is blocked.")
        if ip_obj.is_multicast:
            raise SSARFViolationError(f"Multicast IP address {resolved_ip} is blocked.")
        if ip_obj.is_reserved:
            raise SSARFViolationError(f"Reserved IP address {resolved_ip} is blocked.")

        # Specific cloud metadata checks
        # 169.254.169.254 is covered by is_link_local, but we can be explicit
        if str(ip_obj) == "169.254.169.254":
            raise SSARFViolationError("Cloud metadata IP address is blocked.")
            
        canonical_url = parsed.geturl()
        return canonical_url, resolved_ip
