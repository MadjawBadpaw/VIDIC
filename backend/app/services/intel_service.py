from ipaddress import ip_address

from app.intel.domain_lookup import lookup_domain, lookup_ip


def is_private_ip(ip: str) -> bool:
    """Return True if IP is private/reserved."""
    try:
        addr = ip_address(ip)

        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )

    except Exception:
        return False


def enrich_analysis(iocs: dict, routing):
    """
    Build online intelligence for domains and PUBLIC IPs only.

    Supports:
        routing = {"received_chain": [...]}
    or
        routing = [...]
    """

    # ---------------- Domains ----------------

    domains = sorted(set(iocs.get("domains", [])))

    domain_results = [
        lookup_domain(domain)
        for domain in domains
    ]

    # ---------------- Routing chain ----------------

    if isinstance(routing, dict):
        received_chain = routing.get("received_chain", [])

    elif isinstance(routing, list):
        received_chain = routing

    else:
        received_chain = []

    # ---------------- Public IPs ----------------

    public_ips = []

    for hop in received_chain:

        if not isinstance(hop, dict):
            continue

        ip = hop.get("ip")

        if not ip:
            continue

        if is_private_ip(ip):
            continue

        if ip not in public_ips:
            public_ips.append(ip)

    # ---------------- IP Intelligence ----------------

    ip_results = [
        lookup_ip(ip)
        for ip in public_ips
    ]

    # ---------------- Final Result ----------------

    return {
        "online_lookup": True,
        "lookup_provider": "RDAP + IPWhois",
        "domains": domain_results,
        "ips": ip_results,
    }