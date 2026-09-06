import re
import ipaddress
from email.utils import parsedate_to_datetime
from datetime import timezone

# IPv4 regex
IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _classify_ip(ip: str) -> str:
    """Return public/private/loopback/etc."""

    try:
        addr = ipaddress.ip_address(ip)

        if addr.is_private:
            return "private"
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link_local"
        if addr.is_multicast:
            return "multicast"
        if addr.is_reserved:
            return "reserved"

        return "public"

    except Exception:
        return "unknown"


def _extract_server(header: str) -> str:
    """
    Extract sending mail server.
    Example:
    from smtp.gmail.com (209.85.xxx.xxx)
    """

    match = re.search(r"from\s+([^\s(;]+)", header, re.IGNORECASE)

    if match:
        return match.group(1)

    return "unknown"


def _extract_timestamp(header: str):
    """Parse timestamp after the last semicolon."""

    try:
        if ";" not in header:
            raise ValueError()

        raw_date = header.rsplit(";", 1)[1].strip()

        dt = parsedate_to_datetime(raw_date)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return {
            "iso": dt.isoformat(),
            "display": dt.strftime("%d %b %Y • %H:%M UTC"),
        }

    except Exception:
        return {
            "iso": None,
            "display": None,
        }


def parse_received_headers(message):
    """
    Parse RFC5322 Received headers into routing hops.
    Returns newest hop first (same order as email headers).
    """

    received_headers = message.get_all("Received") or []

    chain = []

    for hop, header in enumerate(received_headers, start=1):

        ips = IP_REGEX.findall(header)

        selected_ip = None
        ip_type = "unknown"

        # Prefer first public IP. If none exist, keep first private IP.
        for ip in ips:
            kind = _classify_ip(ip)

            if kind == "public":
                selected_ip = ip
                ip_type = kind
                break

            if selected_ip is None:
                selected_ip = ip
                ip_type = kind

        chain.append(
            {
                "hop": hop,
                "server": _extract_server(header),
                "ip": selected_ip,
                "ip_type": ip_type,
                "timestamp": _extract_timestamp(header),
                "raw": header,
            }
        )

    return chain