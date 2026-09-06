from datetime import datetime, timezone
import ipaddress
from typing import Optional

import httpx
import tldextract
from dateutil.parser import parse as parse_date
from ipwhois import IPWhois


# ==========================================================
# Configuration
# ==========================================================

TIMEOUT = 10

# IANA RDAP bootstrap registry
IANA_RDAP = "https://data.iana.org/rdap/dns.json"

# Cached bootstrap data.
# Loaded once and reused for subsequent domain lookups.
_RDAP_CACHE: Optional[dict] = None


# ==========================================================
# Helpers
# ==========================================================

def registered_domain(domain: str) -> str:
    """
    Convert a hostname into its registrable/root domain.

    Example:
        login.example.co.uk -> example.co.uk
        example.com         -> example.com
    """

    domain = (domain or "").strip().lower().rstrip(".")

    ext = tldextract.extract(domain)

    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()

    return domain


def _get_rdap_bootstrap() -> Optional[dict]:
    """
    Download IANA RDAP bootstrap data once and cache it.
    """

    global _RDAP_CACHE

    if _RDAP_CACHE is not None:
        return _RDAP_CACHE

    try:
        response = httpx.get(
            IANA_RDAP,
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={
                "User-Agent": "VIDIC/1.0.0"
            },
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            return None

        if not isinstance(data.get("services"), list):
            return None

        _RDAP_CACHE = data

        return _RDAP_CACHE

    except (httpx.HTTPError, ValueError):
        return None


def get_rdap_server(tld: str) -> Optional[str]:
    """
    Resolve the correct RDAP server for a TLD using IANA bootstrap data.
    """

    tld = (tld or "").lower().lstrip(".")

    bootstrap = _get_rdap_bootstrap()

    if not bootstrap:
        return None

    for service in bootstrap.get("services", []):
        if not isinstance(service, list) or len(service) != 2:
            continue

        tlds, urls = service

        if not isinstance(tlds, list):
            continue

        if not isinstance(urls, list) or not urls:
            continue

        if tld in {str(item).lower() for item in tlds}:
            return str(urls[0]).rstrip("/")

    return None


def _extract_registrar(rdap: dict) -> Optional[str]:
    """
    Extract registrar name from RDAP entities.

    Prefer an entity explicitly marked with the registrar role.
    Fall back to a usable entity name when a registry does not
    expose the role consistently.
    """

    fallback = None

    for entity in rdap.get("entities", []):
        if not isinstance(entity, dict):
            continue

        vcard = entity.get("vcardArray")

        if not isinstance(vcard, list) or len(vcard) < 2:
            continue

        fields = vcard[1]

        if not isinstance(fields, list):
            continue

        name = None

        for field in fields:
            if (
                isinstance(field, list)
                and len(field) >= 4
                and field[0] == "fn"
            ):
                name = field[3]
                break

        if not name:
            continue

        roles = entity.get("roles", [])
        if not isinstance(roles, list):
            roles = []

        roles = {str(role).lower() for role in roles}

        if "registrar" in roles:
            return str(name)

        if fallback is None:
            fallback = str(name)

    return fallback


def _extract_registration_date(rdap: dict) -> Optional[str]:
    """
    Extract the registration event date.
    """

    for event in rdap.get("events", []):
        if not isinstance(event, dict):
            continue

        if event.get("eventAction") == "registration":
            event_date = event.get("eventDate")

            if event_date:
                return str(event_date)

    return None


def _calculate_age_days(created: Optional[str]) -> Optional[int]:
    """
    Calculate domain age from its RDAP registration date.
    """

    if not created:
        return None

    try:
        created_dt = parse_date(created)

        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        age = (now - created_dt).days

        return max(age, 0)

    except (ValueError, TypeError, OverflowError):
        return None


def _domain_result(
    domain: str,
    tld: str,
    status: str,
    registrar: Optional[str] = None,
    created: Optional[str] = None,
    age_days: Optional[int] = None,
):
    """
    Build a consistent domain intelligence response.
    """

    is_recent_domain = (
        age_days is not None and age_days < 30
    )

    return {
        "domain": domain,
        "registrar": registrar,
        "created": created,
        "age_days": age_days,
        "is_recent_domain": is_recent_domain,
        "tld": tld,
        "status": status,
    }


# ==========================================================
# Domain RDAP Lookup
# ==========================================================

def lookup_domain(domain: str):
    """
    Perform live RDAP lookup for a domain.

    Status values:
        registered
        recent_domain
        not_registered
        lookup_failed
        unsupported_tld
        http_<status>
    """

    domain = registered_domain(domain)

    if not domain:
        return _domain_result(
            domain=domain,
            tld="",
            status="lookup_failed",
        )

    parts = domain.rsplit(".", 1)

    if len(parts) != 2:
        return _domain_result(
            domain=domain,
            tld="",
            status="lookup_failed",
        )

    tld = parts[-1].lower()

    rdap_server = get_rdap_server(tld)

    if not rdap_server:
        return _domain_result(
            domain=domain,
            tld=tld,
            status="unsupported_tld",
        )

    try:
        response = httpx.get(
            f"{rdap_server}/domain/{domain}",
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={
                "User-Agent": "VIDIC/1.0.0",
                "Accept": "application/rdap+json, application/json",
            },
        )

        # Registry says the domain does not exist.
        if response.status_code == 404:
            return _domain_result(
                domain=domain,
                tld=tld,
                status="not_registered",
            )

        # Preserve meaningful HTTP failures.
        if response.status_code in (401, 403, 429):
            return _domain_result(
                domain=domain,
                tld=tld,
                status=f"http_{response.status_code}",
            )

        response.raise_for_status()

        rdap = response.json()

        if not isinstance(rdap, dict):
            return _domain_result(
                domain=domain,
                tld=tld,
                status="lookup_failed",
            )

        registrar = _extract_registrar(rdap)

        created = _extract_registration_date(rdap)

        age_days = _calculate_age_days(created)

        if age_days is not None and age_days < 30:
            status = "recent_domain"
        else:
            status = "registered"

        return _domain_result(
            domain=domain,
            tld=tld,
            status=status,
            registrar=registrar,
            created=created,
            age_days=age_days,
        )

    except httpx.TimeoutException:
        return _domain_result(
            domain=domain,
            tld=tld,
            status="lookup_failed",
        )

    except httpx.HTTPStatusError as exc:
        return _domain_result(
            domain=domain,
            tld=tld,
            status=f"http_{exc.response.status_code}",
        )

    except (httpx.HTTPError, ValueError, TypeError):
        return _domain_result(
            domain=domain,
            tld=tld,
            status="lookup_failed",
        )

    except Exception:
        return _domain_result(
            domain=domain,
            tld=tld,
            status="lookup_failed",
        )


# ==========================================================
# IP Lookup
# ==========================================================

def lookup_ip(ip: str):
    """
    Perform live IP intelligence lookup using IPWhois.

    Private/internal IPs are identified locally and are not sent
    to the external IP intelligence provider.
    """

    ip = (ip or "").strip()

    try:
        addr = ipaddress.ip_address(ip)

        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        ):
            return {
                "ip": ip,
                "asn": None,
                "organization": None,
                "network_country": None,
                "cidr": None,
                "network_name": None,
                "hosting": None,
                "status": "private_ip",
            }

    except ValueError:
        return {
            "ip": ip,
            "asn": None,
            "organization": None,
            "network_country": None,
            "cidr": None,
            "network_name": None,
            "hosting": None,
            "status": "invalid_ip",
        }

    try:
        result = IPWhois(ip).lookup_rdap(depth=1)

        network = result.get("network") or {}

        organization = (
            result.get("asn_description")
            or network.get("name")
        )

        hosting = False

        if organization:
            organization_lower = organization.lower()

            # Infrastructure-provider identification only.
            # This does NOT determine whether an IP is malicious.
            infrastructure_terms = (
                "amazon",
                "aws",
                "google",
                "cloudflare",
                "microsoft",
                "azure",
                "oracle",
                "digitalocean",
                "hetzner",
                "linode",
                "ovh",
                "vultr",
                "akamai",
                "fastly",
                "leaseweb",
                "contabo",
                "scaleway",
            )

            hosting = any(
                term in organization_lower
                for term in infrastructure_terms
            )

        return {
            "ip": ip,
            "asn": result.get("asn"),
            "organization": organization,
            "network_country": (
                network.get("country")
                or result.get("asn_country_code")
            ),
            "cidr": network.get("cidr"),
            "network_name": network.get("name"),
            "hosting": hosting,
            "status": "ok",
        }

    except IPWhois.exceptions.IPDefinedError:
        return {
            "ip": ip,
            "asn": None,
            "organization": None,
            "network_country": None,
            "cidr": None,
            "network_name": None,
            "hosting": None,
            "status": "invalid_ip",
        }

    except Exception:
        return {
            "ip": ip,
            "asn": None,
            "organization": None,
            "network_country": None,
            "cidr": None,
            "network_name": None,
            "hosting": None,
            "status": "lookup_failed",
        }