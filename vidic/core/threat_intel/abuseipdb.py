# AbuseIPDB client (Phase 3)

from __future__ import annotations

import requests

from vidic.core.threat_intel.cache import IOCCache

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
HIGH_RISK_THRESHOLD = 30


class AbuseIPDBClient:
    def __init__(self, api_key, cache=None):
        self.api_key = api_key
        self.cache = cache or IOCCache()

    def check_ip(self, ip):
        cached = self.cache.get(ip, 'ip', 'abuseipdb')
        if cached is not None:
            return cached

        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        try:
            resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=15)
        except requests.RequestException as exc:
            return {'checked': False, 'error': str(exc)}

        if resp.status_code == 200:
            try:
                data = resp.json()['data']
            except (KeyError, ValueError) as exc:
                return {'checked': False, 'error': f'Unexpected response shape: {exc}'}
            score = data.get('abuseConfidenceScore', 0)
            result = {
                'checked': True,
                'abuse_confidence_score': score,
                'is_high_risk': score >= HIGH_RISK_THRESHOLD,
                'isp': data.get('isp', ''),
                'country_code': data.get('countryCode', ''),
                'total_reports': data.get('totalReports', 0),
            }
        elif resp.status_code == 429:
            result = {'checked': False, 'error': 'Rate limited by AbuseIPDB (429)'}
        else:
            result = {'checked': False, 'error': f'HTTP {resp.status_code}: {resp.text[:200]}'}

        self.cache.set(ip, 'ip', 'abuseipdb', result)
        return result