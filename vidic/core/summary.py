# Summary Generator (Phase 5, pulled forward)
#
# Turns fired risk rules and raw IOCs into plain-language explanations
# for someone with little to no security background. Every sentence is
# a fixed template tied to a specific computed fact - no LLM, nothing
# invented, fully auditable back to the rule/data that produced it.

from __future__ import annotations

VERDICT_EXPLANATIONS = {
    'Safe': 'No significant threat indicators were found in this email. Standard caution is still recommended.',
    'Suspicious': 'Some indicators suggest this email may not be fully legitimate. Verify the sender through a separate channel before acting on anything it asks.',
    'High Risk': 'Multiple strong indicators of phishing or spoofing were found. Do not click links, open attachments, or reply with sensitive information.',
    'Critical Phishing': 'This email shows severe, multiple signs of being malicious. Do not interact with it in any way - report and delete it.',
}

RULE_EXPLANATIONS = {
    'dmarc_failure': (
        "The sender's domain publishes a DMARC policy telling mail servers what to do "
        "when a message can't be verified - and this message failed that check. "
        'A legitimate email from this domain should have passed.'
    ),
    'dkim_failure': (
        'This email carried a DKIM signature (a cryptographic seal meant to prove the '
        "message wasn't altered after sending), but that signature did not verify. "
        'Either the content was tampered with, or the signature was forged.'
    ),
    'spf_failure': (
        "SPF checks whether the server that actually sent this email is one the sender's "
        "domain has authorized to send mail on its behalf. This one was not - meaning the "
        'true sending server is not who it claims to be.'
    ),
    'return_path_from_mismatch': (
        "The address shown in the From field doesn't match the Return-Path address "
        '(where replies and bounces actually go). Legitimate senders almost always match '
        'these - a mismatch is a common spoofing technique.'
    ),
    'urlhaus_detection': (
        'A link in this email matches an entry in URLhaus, a public database of URLs '
        'known to have distributed malware or hosted phishing pages.'
    ),
    'virustotal_detection': (
        'A link or attachment in this email was flagged as malicious by multiple '
        'antivirus engines on VirusTotal.'
    ),
    'abuseipdb_high': (
        'The server that sent this email has a high abuse score on AbuseIPDB, meaning '
        "it's been repeatedly reported for spam, attacks, or other malicious activity."
    ),
    'recent_domain': (
        "The sender's domain was registered very recently. Legitimate organizations "
        "rarely send from a domain that's only days old - this is a common pattern in "
        'throwaway phishing infrastructure.'
    ),
    'executable_attachment': (
        'This email includes an attachment type (executable or macro-enabled document) '
        "that can run code on your computer if opened. This is one of the most common ways "
        'malware is delivered by email.'
    ),
    'classifier_high_confidence': (
        "VIDIC's local phishing-language model rated the wording of this email as highly "
        'characteristic of phishing (urgency, credential requests, impersonation patterns, etc).'
    ),
    'classifier_moderate_confidence': (
        "VIDIC's local phishing-language model rated the wording of this email as "
        'somewhat characteristic of phishing, though not conclusively.'
    ),
}

IOC_TYPE_LABELS = {
    'url': 'Link',
    'domain': 'Domain',
    'ip': 'IP address',
    'email': 'Email address',
    'hash': 'Attachment fingerprint',
}

IOC_TYPE_EXPLANATIONS = {
    'url': 'A web link in this email. Hover before clicking - phishing links often lead to fake login pages.',
    'domain': "The website domain a link points to. Check carefully for lookalike spelling of a brand you trust.",
    'ip': 'A server address this email passed through on its way to you.',
    'email': "An email address associated with this message (sender, reply-to, or mentioned in the body).",
    'hash': 'A unique fingerprint of an attached file, used to check it against malware databases.',
}


def build_plain_summary(risk, auth, iocs):
    lines = []
    verdict_text = VERDICT_EXPLANATIONS.get(risk.verdict, '')
    lines.append(f'{risk.verdict} ({risk.score}/100). {verdict_text}')

    if risk.fired_rules:
        lines.append('')
        lines.append('Why this score:')
        for rule in risk.fired_rules:
            explanation = RULE_EXPLANATIONS.get(rule.name, rule.detail)
            lines.append(f'  - {explanation}')
    else:
        lines.append('')
        lines.append('No red flags were detected by any check VIDIC ran.')

    suspicious_iocs = [i for i in iocs if i.type in ('url', 'domain', 'ip')]
    if suspicious_iocs and risk.score >= 40:
        lines.append('')
        lines.append(
            f'This email also contains {len(suspicious_iocs)} link/domain/IP indicator(s) '
            'worth reviewing individually below before deciding whether to trust it.'
        )
    return lines


def build_recommendations(risk, auth):
    recs = []
    if risk.score >= 70:
        recs.append('Do not click any links or open any attachments in this email.')
    if any(r.name in ('dmarc_failure', 'spf_failure', 'return_path_from_mismatch') for r in risk.fired_rules):
        recs.append(f"Contact the supposed sender ({auth.from_domain or 'the domain'}) through a known, separate channel to confirm they sent this.")
    if any(r.name == 'executable_attachment' for r in risk.fired_rules):
        recs.append('Do not open the attachment. If you already did, disconnect from the network and run a full antivirus scan.')
    if risk.score < 40 and not risk.fired_rules:
        recs.append('No action required, but stay alert for follow-up emails escalating urgency.')
    if not recs:
        recs.append('Review the flagged indicators below before deciding whether to trust this email.')
    return recs[:5]