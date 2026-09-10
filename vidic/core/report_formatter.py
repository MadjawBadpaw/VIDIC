# Report Formatter (extracted from main_window - pure text building,
# no Qt). Assembles the full investigation report shown in the app
# and saved to History.

from __future__ import annotations

from vidic.core.summary import build_plain_summary, build_recommendations, IOC_TYPE_LABELS, IOC_TYPE_EXPLANATIONS

SERVICE_INFO = {
    'virustotal': ('VirusTotal', 'Scans links and attachment hashes against 70+ antivirus engines.'),
    'abuseipdb': ('AbuseIPDB', 'Checks whether the sending IP has a history of abuse reports.'),
    'urlhaus': ('URLhaus', 'Checks links against a database of known malware/phishing URLs.'),
    'rdap': ('RDAP (Domain Age)', 'Checks how recently the sender domain was registered.'),
}


def format_report(parsed, auth, iocs, risk, threat_intel_by_service=None) -> str:
    threat_intel_by_service = threat_intel_by_service or {}
    lines = ['=' * 60, f'  VERDICT: {risk.verdict.upper()}  ({risk.score}/100)', '=' * 60, '']

    lines += build_plain_summary(risk, auth, iocs)

    lines += ['', '--- What should I do? ---']
    for rec in build_recommendations(risk, auth):
        lines.append(f'  * {rec}')

    lines += ['', '', '=' * 60, '  TECHNICAL DETAILS', '=' * 60]

    lines += ['', '--- Email Info ---',
        f"Subject:      {parsed.subject}",
        f"From:         {parsed.sender}",
        f"Return-Path:  {parsed.return_path}",
        f"To:           {', '.join(parsed.recipients)}",
        f"Date:         {parsed.date}",
    ]

    lines += ['', '--- Authentication (raw results) ---',
        f"SPF:    {auth.spf.result} (domain checked: {auth.spf.domain or 'n/a'})",
        f"DKIM:   {'valid' if auth.dkim.valid else ('checked, invalid' if auth.dkim.checked else 'not signed')}",
        f"DMARC:  {'no record published' if not auth.dmarc.record_found else ('pass' if auth.dmarc.passed else 'fail')} "
        f"(policy: {auth.dmarc.policy or 'n/a'})",
        f"Return-Path/From mismatch: {auth.return_path_from_mismatch}",
    ]

    lines += ['', f'--- Indicators of Compromise ({len(iocs)}) ---']
    if not iocs:
        lines.append('  None found.')
    for ioc in iocs:
        label = IOC_TYPE_LABELS.get(ioc.type, ioc.type)
        explanation = IOC_TYPE_EXPLANATIONS.get(ioc.type, '')
        lines.append(f'  [{label}] {ioc.value}')
        lines.append(f'      {explanation}')
        lines.append(f'      Found in: {ioc.source}')

    any_threat_intel = any(threat_intel_by_service.values())
    if any_threat_intel:
        lines += ['', '=' * 60, '  THREAT INTELLIGENCE (per service)', '=' * 60]
        for service_key, (service_name, service_desc) in SERVICE_INFO.items():
            results = threat_intel_by_service.get(service_key, [])
            if not results:
                continue
            lines += ['', f'--- {service_name} ---', f'  ({service_desc})']
            for r in results:
                lines.append(f'  {r}')

    if parsed.attachments:
        lines += ['', '--- Attachments ---']
        for a in parsed.attachments:
            lines.append(f"  {a.filename} ({a.content_type}, {a.size_bytes}B)")
            lines.append(f"      SHA-256: {a.sha256}")

    return "\n".join(lines)