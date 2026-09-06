import re

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"


def parse_received_headers(message):

    received_headers = message.get_all("Received", [])

    hops = []

    for index, header in enumerate(received_headers, start=1):

        ip_match = re.search(IP_REGEX, header)
        ip = ip_match.group(0) if ip_match else None

        server = "Unknown"

        if "from " in header:
            try:
                server = header.split("from ")[1].split(" ")[0]
            except Exception:
                pass

        timestamp = None

        if ";" in header:
            timestamp = header.split(";")[-1].strip()

        hops.append(
            {
                "hop": index,
                "server": server,
                "ip": ip,
                "timestamp": timestamp,
                "raw": header,
            }
        )

    return hops


def get_origin_ip(hops):
    for hop in reversed(hops):
        ip = hop["ip"]

        if not ip:
            continue

        if not (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
            or ip.startswith("127.")
        ):
            return ip

    return None