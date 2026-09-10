# URLhaus client (Phase 3)
#
# Known phishing/malware URL database lookup. As of abuse.ch's 2024/25
# "Community First" authentication rollout, this now DOES require a
# free Auth-Key (get one at https://auth.abuse.ch/) - the original PBR
# noted "no key required," which was accurate when written but is no
# longer current. Sent via the "Auth-Key" HTTP header.

from __future__ import annotations

import requests

from vidic.core.threat_intel.cache import IOCCache

URLHAUS_URL = 'https://urlhaus-api.abuse.ch/v1/url/'


class URLhausClient:
    def __init__(self, api_key, cache=None):
        self.api_key = api_key
        self.cache = cache or IOCCache()

    def check_url(self, url):
        cached = self.cache.get(url, 'url', 'urlhaus')
        if cached is not None:
            return cached

        try:
            resp = requests.post(
                URLHAUS_URL,
                data={'url': url},
                headers={'Auth-Key': self.api_key},
                timeout=15,
            )
        except requests.RequestException as exc:
            return {'checked': False, 'error': str(exc)}

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError as exc:
                return {'checked': False, 'error': f'Unexpected response shape: {exc}'}
            found = data.get('query_status') == 'ok'
            result = {
                'checked': True,
                'found': found,
                'threat': data.get('threat', '') if found else '',
                'tags': data.get('tags', []) if found else [],
            }
        elif resp.status_code == 401:
            result = {'checked': False, 'error': 'Unauthorized (401) - check your URLhaus Auth-Key'}
        else:
            result = {'checked': False, 'error': f'HTTP {resp.status_code}: {resp.text[:200]}'}

        self.cache.set(url, 'url', 'urlhaus', result)
        return result