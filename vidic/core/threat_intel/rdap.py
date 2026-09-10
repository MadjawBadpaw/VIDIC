# RDAP / IPWhois client (Phase 3)
#
# Domain registration age, registrar, ASN, country via RDAP (the
# modern successor to WHOIS - structured JSON, no scraping). No API
# key required. Feeds the "Recent Domain (< 30 days)" risk rule.

from __future__ import annotations

from datetime import datetime, timezone

import requests

from vidic.core.threat_intel.cache import IOCCache

RDAP_BASE = 'https://rdap.org/domain'
RECENT_DOMAIN_THRESHOLD_DAYS = 30


class RDAPClient:
    def __init__(self, cache=None):
        self.cache = cache or IOCCache()

    def lookup_domain(self, domain):
        cached = self.cache.get(domain, 'domain', 'rdap')
        if cached is not None:
            return cached

        try:
            resp = requests.get(f'{RDAP_BASE}/{domain}', timeout=15)
        except requests.RequestException as exc:
            result = {'checked': False, 'error': str(exc)}
            self.cache.set(domain, 'domain', 'rdap', result)
            return result

        if resp.status_code == 404:
            result = {'checked': True, 'found': False}
            self.cache.set(domain, 'domain', 'rdap', result)
            return result

        if resp.status_code != 200:
            result = {'checked': False, 'error': f'HTTP {resp.status_code}'}
            self.cache.set(domain, 'domain', 'rdap', result)
            return result

        try:
            data = resp.json()
        except ValueError as exc:
            result = {'checked': False, 'error': f'Unexpected response shape: {exc}'}
            self.cache.set(domain, 'domain', 'rdap', result)
            return result

        registration_date = None
        for event in data.get('events', []):
            if event.get('eventAction') == 'registration':
                registration_date = event.get('eventDate')
                break

        age_days = None
        is_recent = False
        if registration_date:
            try:
                reg_dt = datetime.fromisoformat(registration_date.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - reg_dt).days
                is_recent = age_days < RECENT_DOMAIN_THRESHOLD_DAYS
            except ValueError:
                pass

        registrar = ''
        for entity in data.get('entities', []):
            if 'registrar' in entity.get('roles', []):
                registrar = RDAPClient._extract_name_from_vcard(entity) or entity.get('handle', '')
                break

        result = {
            'checked': True,
            'found': True,
            'registration_date': registration_date,
            'age_days': age_days,
            'is_recent_domain': is_recent,
            'registrar': registrar,
        }
        self.cache.set(domain, 'domain', 'rdap', result)
        return result

    @staticmethod
    def _extract_name_from_vcard(entity):
        vcard_array = entity.get('vcardArray')
        if not vcard_array or len(vcard_array) < 2:
            return ''
        for prop in vcard_array[1]:
            if len(prop) >= 4 and prop[0] == 'fn':
                return prop[3]
        return ''