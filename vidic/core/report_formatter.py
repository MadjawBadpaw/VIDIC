# Report Formatter - builds a styled HTML report (rendered by QTextEdit
# via setHtml, still fully copyable as plain text with Ctrl+C).
# All dynamic values are HTML-escaped since email content is
# untrusted input.

from __future__ import annotations

import html as html_lib

from vidic.core.summary import build_plain_summary, build_recommendations, IOC_TYPE_LABELS, IOC_TYPE_EXPLANATIONS

SERVICE_INFO = {
    'virustotal': ('VirusTotal', 'Scans links and attachment hashes against 70+ antivirus engines.'),
    'abuseipdb': ('AbuseIPDB', 'Checks whether the sending IP has a history of abuse reports.'),
    'urlhaus': ('URLhaus', 'Checks links against a database of known malware/phishing URLs.'),
    'rdap': ('RDAP (Domain Age)', 'Checks how recently the sender domain was registered.'),
}

VERDICT_COLORS = {
    'Safe': ('#e8f5e9', '#2e7d32'),
    'Suspicious': ('#fff3e0', '#ef6c00'),
    'High Risk': ('#ffe0d6', '#c62828'),
    'Critical Phishing': ('#ffcdd2', '#8e0000'),
}

STATUS_COLORS = {
    'FLAGGED': ('#ffcdd2', '#8e0000'),
    'RECENTLY REGISTERED': ('#ffcdd2', '#8e0000'),
    'Below threshold': ('#fff3e0', '#ef6c00'),
    'Clean': ('#e8f5e9', '#2e7d32'),
    'Established': ('#e8f5e9', '#2e7d32'),
    'Check failed': ('#eeeeee', '#616161'),
}

IOC_TYPE_COLORS = {
    'url': ('#e3f2fd', '#1565c0'),
    'domain': ('#e3f2fd', '#1565c0'),
    'ip': ('#f3e5f5', '#6a1b9a'),
    'email': ('#e0f2f1', '#00695c'),
    'hash': ('#f5f5f5', '#424242'),
}


def _esc(value):
    return html_lib.escape(str(value)) if value is not None else ''


def _badge(text, bg, fg):
    return (
        f'<span style="background-color:{bg}; color:{fg}; padding:2px 8px; '
        f'border-radius:10px; font-size:9pt; font-weight:bold;">{_esc(text)}</span>'
    )


def format_report_html(parsed, auth, iocs, risk, threat_intel_by_service=None):
    threat_intel_by_service = threat_intel_by_service or {}
    verdict_bg, verdict_fg = VERDICT_COLORS.get(risk.verdict, ('#eeeeee', '#333333'))

    parts = ['<div style="font-family: Segoe UI, Arial, sans-serif; font-size: 10pt; color: #222;">']

    parts.append(
        f'<div style="background-color:{verdict_bg}; color:{verdict_fg}; padding:14px 18px; '
        f'border-radius:8px; margin-bottom:14px;">'
        f'<div style="font-size:15pt; font-weight:bold;">{_esc(risk.verdict.upper())}</div>'
        f'<div style="font-size:11pt;">Risk score: {risk.score}/100</div>'
        f'</div>'
    )

    summary_lines = build_plain_summary(risk, auth, iocs)
    parts.append(f'<p>{_esc(summary_lines[0])}</p>')

    if risk.fired_rules:
        parts.append('<p><b>Why this score:</b></p><ul>')
        for rule_line in summary_lines[2:]:
            if rule_line.startswith('  - '):
                parts.append(f'<li>{_esc(rule_line[4:])}</li>')
        parts.append('</ul>')
    else:
        parts.append('<p>No red flags were detected by any check VIDIC ran.</p>')

    parts.append('<p><b>What should I do?</b></p><ul>')
    for rec in build_recommendations(risk, auth):
        parts.append(f'<li>{_esc(rec)}</li>')
    parts.append('</ul>')

    parts.append('<hr style="border: 1px solid #ddd; margin: 18px 0;">')
    parts.append('<h2 style="font-size:12pt;">Technical Details</h2>')

    parts.append('<h3 style="font-size:11pt;">Email Info</h3>')
    parts.append('<table cellpadding="4" style="border-collapse: collapse;">')
    for field_label, field_value in [
        ('Subject', parsed.subject), ('From', parsed.sender),
        ('Return-Path', parsed.return_path), ('To', ', '.join(parsed.recipients)),
        ('Date', parsed.date),
    ]:
        parts.append(f'<tr><td style="color:#666;"><b>{_esc(field_label)}</b></td><td>{_esc(field_value)}</td></tr>')
    parts.append('</table>')

    parts.append('<h3 style="font-size:11pt;">Authentication</h3>')
    parts.append('<table cellpadding="4" style="border-collapse: collapse;">')
    spf_ok = auth.spf.result == 'pass'
    dkim_status = 'valid' if auth.dkim.valid else ('invalid' if auth.dkim.checked else 'not signed')
    dmarc_status = 'no record' if not auth.dmarc.record_found else ('pass' if auth.dmarc.passed else 'fail')

    for row_label, row_value, is_bad in [
        ('SPF', f"{auth.spf.result} (domain: {auth.spf.domain or 'n/a'})", not spf_ok and auth.spf.checked),
        ('DKIM', dkim_status, auth.dkim.checked and not auth.dkim.valid),
        ('DMARC', f"{dmarc_status} (policy: {auth.dmarc.policy or 'n/a'})", auth.dmarc.record_found and not auth.dmarc.passed),
        ('Return-Path/From mismatch', str(auth.return_path_from_mismatch), auth.return_path_from_mismatch),
    ]:
        bg, fg = ('#ffe0e0', '#c62828') if is_bad else ('#e8f5e9', '#2e7d32')
        parts.append(
            f'<tr><td style="color:#666;"><b>{_esc(row_label)}</b></td>'
            f'<td>{_badge(row_value, bg, fg)}</td></tr>'
        )
    parts.append('</table>')

    parts.append(f'<h3 style="font-size:11pt;">Indicators of Compromise ({len(iocs)})</h3>')
    if not iocs:
        parts.append('<p style="color:#666;">None found.</p>')
    else:
        parts.append('<table cellpadding="6" style="border-collapse: collapse; width:100%;">')
        for ioc in iocs:
            label = IOC_TYPE_LABELS.get(ioc.type, ioc.type)
            explanation = IOC_TYPE_EXPLANATIONS.get(ioc.type, '')
            bg, fg = IOC_TYPE_COLORS.get(ioc.type, ('#eee', '#333'))
            parts.append(
                '<tr style="border-bottom: 1px solid #eee;">'
                f'<td style="vertical-align:top;">{_badge(label, bg, fg)}</td>'
                f'<td><b>{_esc(ioc.value)}</b><br>'
                f'<span style="color:#666; font-size:9pt;">{_esc(explanation)} '
                f'&mdash; found in: {_esc(ioc.source)}</span></td></tr>'
            )
        parts.append('</table>')

    any_results = any(threat_intel_by_service.values())
    if any_results:
        parts.append('<h2 style="font-size:12pt; margin-top:18px;">Threat Intelligence</h2>')
        for service_key, (service_name, service_desc) in SERVICE_INFO.items():
            results = threat_intel_by_service.get(service_key, [])
            if not results:
                continue
            parts.append(f'<h3 style="font-size:11pt;">{_esc(service_name)}</h3>')
            parts.append(f'<p style="color:#666; font-size:9pt;">{_esc(service_desc)}</p>')
            parts.append('<table cellpadding="4" style="border-collapse: collapse; width:100%;">')
            for item in results:
                bg, fg = STATUS_COLORS.get(item['status'], ('#eee', '#333'))
                parts.append(
                    '<tr>'
                    f'<td>{_badge(item["status"], bg, fg)}</td>'
                    f'<td><b>{_esc(item["value"])}</b></td>'
                    f'<td style="color:#666;">{_esc(item["detail"])}</td>'
                    '</tr>'
                )
            parts.append('</table>')

    if parsed.attachments:
        parts.append('<h3 style="font-size:11pt;">Attachments</h3>')
        parts.append('<table cellpadding="4" style="border-collapse: collapse;">')
        for a in parsed.attachments:
            parts.append(
                f'<tr><td><b>{_esc(a.filename)}</b></td>'
                f'<td style="color:#666;">{_esc(a.content_type)}, {a.size_bytes}B</td></tr>'
                f'<tr><td colspan="2" style="color:#999; font-size:8pt;">SHA-256: {_esc(a.sha256)}</td></tr>'
            )
        parts.append('</table>')

    parts.append('</div>')
    return ''.join(parts)