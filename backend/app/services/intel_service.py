from ipaddress import ip_address

from app.intel.abuseipdb import lookup_abuseipdb
from app.intel.domain_lookup import lookup_domain, lookup_ip


def is_private_ip(ip: str) -> bool:
    """Return True for private, loopback or reserved IPs."""
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
        return True


def enrich_analysis(iocs: dict, routing):
    """
    Enrich extracted IOCs with RDAP, IPWhois and AbuseIPDB.

    Supports:
        routing = {"received_chain": [...]}
        routing = [...]
    """

    # ---------------- Domains ----------------
    domains = sorted(set(iocs.get("domains", [])))
    domain_results = [lookup_domain(domain) for domain in domains]

    # ---------------- Routing chain ----------------
    if isinstance(routing, dict):
        received_chain = routing.get("received_chain", [])
    elif isinstance(routing, list):
        received_chain = routing
    else:
        received_chain = []

    public_ips = []

    for hop in received_chain:
        if not isinstance(hop, dict):
            continue

        ip = hop.get("ip")

        if not ip or is_private_ip(ip):
            continue

        if ip not in public_ips:
            public_ips.append(ip)

    # ---------------- IP Intelligence ----------------
    ip_results = []

    for ip in public_ips:
        ip_info = lookup_ip(ip)
        abuse_info = lookup_abuseipdb(ip)

        ip_info["abuseipdb"] = abuse_info

        ip_results.append(ip_info)

    # CHANGED: `lookup_provider` removed from this return value. It was a
    # hardcoded string that didn't reflect whether each lookup actually
    # succeeded for this specific request. That description now lives as
    # a static field on /health instead.
    return {
        "online_lookup": True,
        "domains": domain_results,
        "ips": ip_results,
    }