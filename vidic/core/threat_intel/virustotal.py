# VirusTotal client (Phase 3)
#
# Check-only GET (does not submit new URLs for scanning). A 404 means
# "VT has no existing record", not "safe". Free tier is ~4 req/min.

from __future__ import annotations

import base64
import time

import requests

from vidic.core.threat_intel.cache import IOCCache

VT_BASE = 'https://www.virustotal.com/api/v3'
MIN_REQUEST_INTERVAL = 16


class VirusTotalClient:
    def __init__(self, api_key, cache=None):
        self.api_key = api_key
        self.cache = cache or IOCCache()
        self._last_request_time = 0.0

    def check_url(self, url):
        cached = self.cache.get(url, 'url', 'virustotal')
        if cached is not None:
            return cached
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        result = self._get(f'{VT_BASE}/urls/{url_id}')
        self.cache.set(url, 'url', 'virustotal', result)
        return result

    def check_hash(self, sha256):
        cached = self.cache.get(sha256, 'hash', 'virustotal')
        if cached is not None:
            return cached
        result = self._get(f'{VT_BASE}/files/{sha256}')
        self.cache.set(sha256, 'hash', 'virustotal', result)
        return result

    def _get(self, url):
        self._throttle()
        try:
            resp = requests.get(url, headers={'x-apikey': self.api_key}, timeout=15)
        except requests.RequestException as exc:
            return {'checked': False, 'error': str(exc)}
        finally:
            self._last_request_time = time.time()

        if resp.status_code == 404:
            return {'checked': True, 'found': False, 'malicious': False, 'malicious_count': 0, 'total_engines': 0}

        if resp.status_code == 200:
            try:
                stats = resp.json()['data']['attributes']['last_analysis_stats']
            except (KeyError, ValueError) as exc:
                return {'checked': False, 'error': f'Unexpected response shape: {exc}'}
            malicious_count = stats.get('malicious', 0) + stats.get('suspicious', 0)
            return {
                'checked': True, 'found': True,
                'malicious': malicious_count > 0,
                'malicious_count': malicious_count,
                'total_engines': sum(stats.values()),
            }

        if resp.status_code == 429:
            return {'checked': False, 'error': 'Rate limited by VirusTotal (429)'}

        return {'checked': False, 'error': f'HTTP {resp.status_code}: {resp.text[:200]}'}

    def _throttle(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)