from ipaddress import ip_address

from ipwhois import IPWhois

HOSTING_KEYWORDS = {
    "amazon",
    "aws",
    "azure",
    "google",
    "cloudflare",
    "oracle",
    "digitalocean",
    "linode",
    "ovh",
    "hetzner",
    "vultr",
    "rackspace",
    "contabo",
    "hostinger",
    "server",
    "hosting",
    "vps",
    "cloud",
}


def is_private_ip(ip: str) -> bool:
    try:
        obj = ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except ValueError:
        return True


def is_likely_hosting(org: str | None, network_name: str | None):
    text = f"{org or ''} {network_name or ''}".lower()

    return any(keyword in text for keyword in HOSTING_KEYWORDS)


def lookup_ip(ip: str):
    if not ip:
        return {"ip": None, "status": "no_ip"}

    if is_private_ip(ip):
        return {
            "ip": ip,
            "status": "private_ip",
        }

    try:
        result = IPWhois(ip).lookup_rdap(depth=1)

        network = result.get("network", {})

        organization = result.get("asn_description")
        network_name = network.get("name")

        return {
            "ip": ip,
            "asn": result.get("asn"),
            "organization": organization,
            "network_country": network.get("country"),
            "cidr": network.get("cidr"),
            "network_name": network_name,
            "hosting": is_likely_hosting(organization, network_name),
            "status": "ok",
        }

    except Exception:
        return {
            "ip": ip,
            "status": "lookup_failed",
        }