# Threat Intel Runner (pure business logic, no Qt).
# Queries VirusTotal / AbuseIPDB / URLhaus / RDAP for whichever IOCs
# match keys the user has saved.
#
# Each per-service result is structured (status/value/detail) rather
# than a pre-formatted string, so the report formatter can render a
# colored status badge instead of just dumping text.

from __future__ import annotations

from vidic.core import secrets


def gather_threat_intel(iocs):
    hits = {'urlhaus': False, 'virustotal': False, 'abuseipdb_high': False, 'recent_domain': False}
    by_service = {'virustotal': [], 'abuseipdb': [], 'urlhaus': [], 'rdap': []}

    vt_key = secrets.get_key('virustotal')
    abuseipdb_key = secrets.get_key('abuseipdb')
    urlhaus_key = secrets.get_key('urlhaus')

    vt_client = None
    if vt_key:
        from vidic.core.threat_intel.virustotal import VirusTotalClient
        vt_client = VirusTotalClient(api_key=vt_key)

    abuseipdb_client = None
    if abuseipdb_key:
        from vidic.core.threat_intel.abuseipdb import AbuseIPDBClient
        abuseipdb_client = AbuseIPDBClient(api_key=abuseipdb_key)

    urlhaus_client = None
    if urlhaus_key:
        from vidic.core.threat_intel.urlhaus import URLhausClient
        urlhaus_client = URLhausClient(api_key=urlhaus_key)

    from vidic.core.threat_intel.rdap import RDAPClient
    rdap_client = RDAPClient()

    for ioc in iocs:
        if ioc.type == 'url':
            if urlhaus_client:
                r = urlhaus_client.check_url(ioc.value)
                if r.get('found'):
                    hits['urlhaus'] = True
                    by_service['urlhaus'].append({'status': 'FLAGGED', 'value': ioc.value, 'detail': f"threat type: {r.get('threat', '?')}"})
                elif r.get('checked'):
                    by_service['urlhaus'].append({'status': 'Clean', 'value': ioc.value, 'detail': 'not found in database'})
                else:
                    by_service['urlhaus'].append({'status': 'Check failed', 'value': ioc.value, 'detail': r.get('error', 'unknown error')})
            if vt_client:
                r = vt_client.check_url(ioc.value)
                if r.get('malicious'):
                    hits['virustotal'] = True
                    by_service['virustotal'].append({'status': 'FLAGGED', 'value': ioc.value, 'detail': f"{r.get('malicious_count')}/{r.get('total_engines')} engines detected"})
                elif r.get('checked') and r.get('found'):
                    by_service['virustotal'].append({'status': 'Below threshold', 'value': ioc.value, 'detail': f"{r.get('malicious_count')}/{r.get('total_engines')} engines flagged"})
                elif r.get('checked'):
                    by_service['virustotal'].append({'status': 'Clean', 'value': ioc.value, 'detail': 'no existing scan record'})
                else:
                    by_service['virustotal'].append({'status': 'Check failed', 'value': ioc.value, 'detail': r.get('error', 'unknown error')})

        elif ioc.type == 'hash' and vt_client:
            r = vt_client.check_hash(ioc.value)
            if r.get('malicious'):
                hits['virustotal'] = True
                by_service['virustotal'].append({'status': 'FLAGGED', 'value': 'attachment hash', 'detail': f"{r.get('malicious_count')}/{r.get('total_engines')} engines detected"})
            elif r.get('checked') and r.get('found'):
                by_service['virustotal'].append({'status': 'Below threshold', 'value': 'attachment hash', 'detail': f"{r.get('malicious_count')}/{r.get('total_engines')} engines flagged"})
            elif r.get('checked'):
                by_service['virustotal'].append({'status': 'Clean', 'value': 'attachment hash', 'detail': 'no existing scan record'})

        elif ioc.type == 'ip' and abuseipdb_client:
            r = abuseipdb_client.check_ip(ioc.value)
            if r.get('checked'):
                status = 'FLAGGED' if r.get('is_high_risk') else 'Clean'
                if r.get('is_high_risk'):
                    hits['abuseipdb_high'] = True
                by_service['abuseipdb'].append({
                    'status': status, 'value': ioc.value,
                    'detail': f"{r.get('abuse_confidence_score')}% abuse confidence, ISP: {r.get('isp', '?')}",
                })
            else:
                by_service['abuseipdb'].append({'status': 'Check failed', 'value': ioc.value, 'detail': r.get('error', 'unknown error')})

        elif ioc.type == 'domain':
            r = rdap_client.lookup_domain(ioc.value)
            if r.get('found'):
                status = 'RECENTLY REGISTERED' if r.get('is_recent_domain') else 'Established'
                if r.get('is_recent_domain'):
                    hits['recent_domain'] = True
                by_service['rdap'].append({
                    'status': status, 'value': ioc.value,
                    'detail': f"registered {r.get('age_days')} days ago via {r.get('registrar', '?')}",
                })
            elif r.get('checked'):
                by_service['rdap'].append({'status': 'Clean', 'value': ioc.value, 'detail': 'no RDAP record found for this domain'})
            else:
                by_service['rdap'].append({'status': 'Check failed', 'value': ioc.value, 'detail': r.get('error', 'unknown error')})

    return hits, by_service