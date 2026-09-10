# Risk Engine (Phase 2, partial)
#
# Weighted, capped (0-100) scoring. Right now this consumes signals from
# the Auth Engine (Phase 1) and attachment inspection (this file).
# Threat-intel hits (Phase 3) and classifier confidence (Phase 2b) are
# optional parameters that slot in later without changing this engine's
# shape - pass them in once those phases exist.
#
# Weight table matches PBR Section 11 exactly.

from __future__ import annotations

from dataclasses import dataclass, field

from vidic.core.auth import AuthResult
from vidic.core.parser import ParsedEmail

WEIGHTS = {
    'dmarc_failure': 25,
    'dkim_failure': 20,
    'spf_failure': 15,
    'return_path_from_mismatch': 15,
    'urlhaus_detection': 20,
    'virustotal_detection': 20,
    'abuseipdb_high': 15,
    'recent_domain': 10,
    'executable_attachment': 15,
    'classifier_high_confidence': 20,
    'classifier_moderate_confidence': 10,
}

VERDICT_THRESHOLDS = [
    (90, 'Critical Phishing'),
    (70, 'High Risk'),
    (40, 'Suspicious'),
    (0, 'Safe'),
]

RISKY_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.jar', '.msi', '.ps1',
    '.docm', '.xlsm', '.pptm', '.dll', '.com', '.hta',
}
RISKY_CONTENT_TYPES = {
    'application/x-msdownload',
    'application/x-executable',
    'application/x-dosexec',
    'application/vnd.ms-word.document.macroenabled.12',
    'application/vnd.ms-excel.sheet.macroenabled.12',
}


@dataclass(frozen=True)
class FiredRule:
    name: str
    weight: int
    detail: str


@dataclass
class RiskAssessment:
    score: int = 0
    verdict: str = 'Safe'
    fired_rules: list[FiredRule] = field(default_factory=list)


class RiskEngine:
    def assess(
        self,
        parsed: ParsedEmail,
        auth: AuthResult,
        threat_intel_hits: dict | None = None,
        classifier_confidence: float | None = None,
    ) -> RiskAssessment:
        fired: list[FiredRule] = []

        if auth.dmarc_failed:
            fired.append(FiredRule(
                'dmarc_failure', WEIGHTS['dmarc_failure'],
                f"DMARC policy '{auth.dmarc.policy}' failed for {auth.from_domain}",
            ))

        if auth.dkim_failed:
            fired.append(FiredRule(
                'dkim_failure', WEIGHTS['dkim_failure'],
                'DKIM signature present but did not verify',
            ))

        if auth.spf_failed:
            fired.append(FiredRule(
                'spf_failure', WEIGHTS['spf_failure'],
                f"SPF check returned '{auth.spf.result}' for {auth.spf.domain}",
            ))

        if auth.return_path_from_mismatch:
            fired.append(FiredRule(
                'return_path_from_mismatch', WEIGHTS['return_path_from_mismatch'],
                f"Return-Path domain ({auth.return_path_domain}) does not match "
                f"From domain ({auth.from_domain})",
            ))

        risky_attachments = [a for a in parsed.attachments if self._is_risky_attachment(a)]
        if risky_attachments:
            names = ', '.join(a.filename for a in risky_attachments)
            fired.append(FiredRule(
                'executable_attachment', WEIGHTS['executable_attachment'],
                f'Executable or macro-enabled attachment(s): {names}',
            ))

        if threat_intel_hits:
            if threat_intel_hits.get('urlhaus'):
                fired.append(FiredRule(
                    'urlhaus_detection', WEIGHTS['urlhaus_detection'],
                    'URL matched a known entry in URLhaus',
                ))
            if threat_intel_hits.get('virustotal'):
                fired.append(FiredRule(
                    'virustotal_detection', WEIGHTS['virustotal_detection'],
                    'URL or attachment hash flagged by VirusTotal',
                ))
            if threat_intel_hits.get('abuseipdb_high'):
                fired.append(FiredRule(
                    'abuseipdb_high', WEIGHTS['abuseipdb_high'],
                    'Originating IP has an AbuseIPDB confidence score of 30 or higher',
                ))
            if threat_intel_hits.get('recent_domain'):
                fired.append(FiredRule(
                    'recent_domain', WEIGHTS['recent_domain'],
                    'Sender domain was registered less than 30 days ago',
                ))

        if classifier_confidence is not None:
            if classifier_confidence > 0.90:
                fired.append(FiredRule(
                    'classifier_high_confidence', WEIGHTS['classifier_high_confidence'],
                    f'Phishing-text classifier confidence: {classifier_confidence:.0%}',
                ))
            elif classifier_confidence >= 0.70:
                fired.append(FiredRule(
                    'classifier_moderate_confidence', WEIGHTS['classifier_moderate_confidence'],
                    f'Phishing-text classifier confidence: {classifier_confidence:.0%}',
                ))

        raw_score = sum(rule.weight for rule in fired)
        score = min(raw_score, 100)
        verdict = self._verdict_for(score)

        return RiskAssessment(score=score, verdict=verdict, fired_rules=fired)

    @staticmethod
    def _is_risky_attachment(attachment) -> bool:
        filename = attachment.filename.lower()
        if any(filename.endswith(ext) for ext in RISKY_EXTENSIONS):
            return True
        return attachment.content_type.lower() in RISKY_CONTENT_TYPES

    @staticmethod
    def _verdict_for(score: int) -> str:
        for threshold, verdict in VERDICT_THRESHOLDS:
            if score >= threshold:
                return verdict
        return 'Safe'