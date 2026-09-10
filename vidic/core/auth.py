"""
Auth Engine (Phase 1)

Independently re-verifies SPF, DKIM, and DMARC for a parsed email —
never trusts the sender's own "Authentication-Results" header, since
that header can be forged by anyone who controls the message.

Requires live DNS (this is the one part of VIDIC's core pipeline that
is NOT offline-capable — Offline/Local-only mode, added in Phase 6,
skips this engine entirely).

Design notes:
- SPF is checked against the *envelope sender* (Return-Path address)
  and the *originating IP*, which we recover from the Received header
  chain rather than trusting any stamped result.
- DKIM is verified byte-for-byte against ParsedEmail.raw_bytes using
  dkimpy, which fetches the public key from DNS itself.
- DMARC alignment is evaluated ourselves (relaxed mode: same
  organizational domain) rather than trusting a receiver's verdict,
  since we do not have access to the recipient's own alignment mode
  preference at analysis time.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from vidic.core.parser import ParsedEmail

# Regex for IPv4 addresses embedded in Received headers, e.g.
# "Received: from mail.example.com (1.2.3.4) by mx.example.com ..."
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")

# DKIM-Signature tag, e.g. "v=1; a=rsa-sha256; d=example.com; s=selector; ..."
_DKIM_DOMAIN_RE = re.compile(r"\bd=([^;\s]+)")


@dataclass
class SPFResult:
    checked: bool = False
    result: str = "none"          # pass / fail / softfail / neutral / none / permerror / temperror / skipped
    domain: str = ""              # envelope-sender domain that was checked
    ip_checked: str = ""          # originating IP used for the check
    error: str = ""


@dataclass
class DKIMResult:
    checked: bool = False
    valid: bool = False
    signing_domain: str = ""      # the d= tag from the DKIM-Signature header
    error: str = ""


@dataclass
class DMARCResult:
    checked: bool = False
    record_found: bool = False
    policy: str = ""              # none / quarantine / reject
    spf_aligned: bool = False
    dkim_aligned: bool = False
    passed: bool = False          # (spf pass AND spf_aligned) OR (dkim pass AND dkim_aligned)
    error: str = ""


@dataclass
class AuthResult:
    from_domain: str = ""
    return_path_domain: str = ""
    return_path_from_mismatch: bool = False

    spf: SPFResult = field(default_factory=SPFResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)

    warnings: list[str] = field(default_factory=list)

    # Convenience flags consumed directly by the Risk Engine (Section 11)
    @property
    def spf_failed(self) -> bool:
        return self.spf.checked and self.spf.result in ("fail", "softfail", "permerror")

    @property
    def dkim_failed(self) -> bool:
        return self.dkim.checked and not self.dkim.valid

    @property
    def dmarc_failed(self) -> bool:
        return self.dmarc.checked and self.dmarc.record_found and not self.dmarc.passed


class AuthEngine:
    """Runs independent SPF/DKIM/DMARC verification against a ParsedEmail."""

    def verify(self, parsed: ParsedEmail) -> AuthResult:
        result = AuthResult()

        from_addr = parseaddr(parsed.sender)[1]
        return_path_addr = parseaddr(parsed.return_path)[1]

        result.from_domain = self._domain_of(from_addr)
        result.return_path_domain = self._domain_of(return_path_addr)

        if result.from_domain and result.return_path_domain:
            result.return_path_from_mismatch = not self._same_base_domain(
                result.from_domain, result.return_path_domain
            )

        origin_ip = self._find_originating_ip(parsed.received_chain)

        result.spf = self._check_spf(
            envelope_sender=return_path_addr or from_addr,
            origin_ip=origin_ip,
        )
        result.dkim = self._check_dkim(parsed.raw_bytes)
        result.dmarc = self._check_dmarc(
            from_domain=result.from_domain,
            spf=result.spf,
            dkim=result.dkim,
        )

        if not origin_ip:
            result.warnings.append(
                "Could not identify an originating public IP from the Received "
                "chain; SPF was skipped."
            )

        return result

    # -- SPF ----------------------------------------------------------

    def _check_spf(self, envelope_sender: str, origin_ip: str | None) -> SPFResult:
        spf_result = SPFResult()
        domain = self._domain_of(envelope_sender)
        spf_result.domain = domain

        if not domain or not origin_ip:
            spf_result.result = "skipped"
            return spf_result

        spf_result.ip_checked = origin_ip

        try:
            import spf as pyspf  # imported lazily; optional at parse-time
        except ImportError:
            spf_result.error = "pyspf is not installed"
            return spf_result

        try:
            verdict, _explanation = pyspf.check2(
                i=origin_ip, s=envelope_sender, h=domain
            )
            spf_result.checked = True
            spf_result.result = verdict
        except Exception as exc:  # noqa: BLE001 - any DNS/library failure -> degrade gracefully
            spf_result.result = "temperror"
            spf_result.error = str(exc)

        return spf_result

    # -- DKIM -----------------------------------------------------------

    def _check_dkim(self, raw_bytes: bytes) -> DKIMResult:
        dkim_result = DKIMResult()

        if b"DKIM-Signature" not in raw_bytes:
            return dkim_result  # not checked: message isn't DKIM-signed

        match = _DKIM_DOMAIN_RE.search(raw_bytes.decode("utf-8", errors="ignore"))
        if match:
            dkim_result.signing_domain = match.group(1).strip()

        try:
            import dkim
        except ImportError:
            dkim_result.error = "dkimpy is not installed"
            return dkim_result

        try:
            dkim_result.checked = True
            dkim_result.valid = dkim.verify(raw_bytes)
        except Exception as exc:  # noqa: BLE001
            dkim_result.valid = False
            dkim_result.error = str(exc)

        return dkim_result

    # -- DMARC ----------------------------------------------------------

    def _check_dmarc(
        self, from_domain: str, spf: SPFResult, dkim: DKIMResult
    ) -> DMARCResult:
        dmarc_result = DMARCResult()

        if not from_domain:
            return dmarc_result

        try:
            import checkdmarc
        except ImportError:
            dmarc_result.error = "checkdmarc is not installed"
            return dmarc_result

        try:
            record = checkdmarc.check_dmarc(from_domain)
        except Exception as exc:  # noqa: BLE001
            dmarc_result.error = str(exc)
            return dmarc_result

        dmarc_result.checked = True

        if not record.get("valid", False):
            # No DMARC record published for this domain — not itself a
            # failure, but leaves the risk engine unable to rely on it.
            dmarc_result.record_found = False
            dmarc_result.error = record.get("error", "no valid DMARC record")
            return dmarc_result

        dmarc_result.record_found = True
        tags = record.get("tags", {})
        dmarc_result.policy = tags.get("p", {}).get("value", "none")

        aspf_mode = tags.get("aspf", {}).get("value", "r")  # r=relaxed, s=strict
        adkim_mode = tags.get("adkim", {}).get("value", "r")

        dmarc_result.spf_aligned = self._is_aligned(
            from_domain, spf.domain, strict=(aspf_mode == "s")
        )
        dmarc_result.dkim_aligned = self._is_aligned(
            from_domain, dkim.signing_domain, strict=(adkim_mode == "s")
        )

        spf_pass = spf.checked and spf.result == "pass"
        dkim_pass = dkim.checked and dkim.valid

        dmarc_result.passed = (spf_pass and dmarc_result.spf_aligned) or (
            dkim_pass and dmarc_result.dkim_aligned
        )

        return dmarc_result

    # -- Shared helpers ---------------------------------------------------

    @staticmethod
    def _domain_of(address: str) -> str:
        if not address or "@" not in address:
            return ""
        return address.rsplit("@", 1)[-1].strip().lower().rstrip(">").strip()

    @staticmethod
    def _same_base_domain(domain_a: str, domain_b: str) -> bool:
        if not domain_a or not domain_b:
            return False
        try:
            import checkdmarc

            return checkdmarc.get_base_domain(domain_a) == checkdmarc.get_base_domain(
                domain_b
            )
        except Exception:  # noqa: BLE001 - fall back to exact match if lib unavailable
            return domain_a.lower() == domain_b.lower()

    def _is_aligned(self, from_domain: str, other_domain: str, strict: bool) -> bool:
        if not from_domain or not other_domain:
            return False
        if strict:
            return from_domain.lower() == other_domain.lower()
        return self._same_base_domain(from_domain, other_domain)

    @staticmethod
    def _find_originating_ip(received_chain: list[str]) -> str | None:
        """
        Scans the Received chain from oldest (origin) to newest, returning
        the first public IP found. Received headers are prepended by each
        hop, so the chain as parsed is newest-first; we walk it in reverse
        to approximate the original sending server.
        """
        for header in reversed(received_chain):
            for candidate in _IPV4_RE.findall(header) + _IPV6_RE.findall(header):
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if ip_obj.is_global:
                    return str(ip_obj)
        return None
