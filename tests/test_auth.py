"""
Tests for the Phase 1 Auth Engine.

External DNS calls (pyspf, dkimpy, checkdmarc) are mocked so this suite
runs fast, offline, and deterministically in CI. Logic that doesn't
need the network — IP-hop detection, domain extraction, alignment
math — is tested directly.
"""

from unittest.mock import MagicMock, patch

from vidic.core.auth import AuthEngine
from vidic.core.parser import EmailParser

SPOOFED_EML = b"""From: "Your Bank" <security@your-bank.com>
To: victim@example.com
Return-Path: <bounce@totally-different-domain.ru>
Subject: Verify your account now
Date: Mon, 07 Sep 2026 10:00:00 +0000
Message-ID: <abc123@totally-different-domain.ru>
Received: from mx.example.com (10.0.0.5) by mail.example.com; Mon, 07 Sep 2026 10:00:02 +0000
Received: from mail-relay.totally-different-domain.ru (185.220.101.45) by mx.example.com; Mon, 07 Sep 2026 10:00:01 +0000
Content-Type: text/plain; charset="utf-8"

Please verify your account immediately.
"""

ALIGNED_EML = b"""From: alerts@example.com
To: victim@example.com
Return-Path: <alerts@example.com>
Subject: Your weekly digest
Date: Mon, 07 Sep 2026 10:00:00 +0000
Message-ID: <xyz@example.com>
Received: from mail-relay.example.com (93.184.216.34) by mx.example.com; Mon, 07 Sep 2026 10:00:01 +0000
Content-Type: text/plain; charset="utf-8"

Here is your weekly digest.
"""


def _engine():
    return AuthEngine()


class TestDomainExtractionAndAlignment:
    def test_return_path_from_mismatch_detected(self):
        parsed = EmailParser().parse_bytes(SPOOFED_EML)
        result = _engine().verify(parsed)

        assert result.from_domain == "your-bank.com"
        assert result.return_path_domain == "totally-different-domain.ru"
        assert result.return_path_from_mismatch is True

    def test_matching_domains_not_flagged(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        result = _engine().verify(parsed)

        assert result.from_domain == "example.com"
        assert result.return_path_domain == "example.com"
        assert result.return_path_from_mismatch is False


class TestOriginatingIPDetection:
    def test_finds_first_public_ip_from_origin_end_of_chain(self):
        parsed = EmailParser().parse_bytes(SPOOFED_EML)
        ip = AuthEngine._find_originating_ip(parsed.received_chain)

        # The private 10.0.0.5 hop (closest to delivery) must be skipped;
        # the public 185.220.101.45 hop (closest to the actual sender) wins.
        assert ip == "185.220.101.45"

    def test_returns_none_when_no_public_ip_present(self):
        chain = ["from internal (10.0.0.1) by internal2 (10.0.0.2)"]
        assert AuthEngine._find_originating_ip(chain) is None

    def test_empty_chain_returns_none(self):
        assert AuthEngine._find_originating_ip([]) is None


class TestSPFWithMockedDNS:
    def test_spf_pass_is_recorded(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        with patch("spf.check2", return_value=("pass", "matched")):
            result = _engine().verify(parsed)

        assert result.spf.checked is True
        assert result.spf.result == "pass"
        assert result.spf_failed is False

    def test_spf_fail_is_recorded(self):
        parsed = EmailParser().parse_bytes(SPOOFED_EML)
        with patch("spf.check2", return_value=("fail", "did not match")):
            result = _engine().verify(parsed)

        assert result.spf.result == "fail"
        assert result.spf_failed is True

    def test_spf_skipped_without_originating_ip(self):
        no_ip_eml = SPOOFED_EML.replace(b"185.220.101.45", b"").replace(b"10.0.0.5", b"")
        parsed = EmailParser().parse_bytes(no_ip_eml)
        result = _engine().verify(parsed)

        assert result.spf.result == "skipped"
        assert any("originating public IP" in w for w in result.warnings)


class TestDKIMWithMockedVerification:
    def test_dkim_valid_true(self):
        signed = ALIGNED_EML.replace(
            b"Content-Type:",
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; c=relaxed/relaxed;\r\nContent-Type:",
        )
        parsed = EmailParser().parse_bytes(signed)
        with patch("dkim.verify", return_value=True):
            result = _engine().verify(parsed)

        assert result.dkim.checked is True
        assert result.dkim.valid is True
        assert result.dkim.signing_domain == "example.com"
        assert result.dkim_failed is False

    def test_dkim_missing_signature_not_checked(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        result = _engine().verify(parsed)

        assert result.dkim.checked is False
        assert result.dkim_failed is False  # absence isn't itself a "failure" flag here

    def test_dkim_invalid_signature(self):
        signed = ALIGNED_EML.replace(
            b"Content-Type:",
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; c=relaxed/relaxed;\r\nContent-Type:",
        )
        parsed = EmailParser().parse_bytes(signed)
        with patch("dkim.verify", return_value=False):
            result = _engine().verify(parsed)

        assert result.dkim.valid is False
        assert result.dkim_failed is True


class TestDMARCWithMockedRecord:
    def test_dmarc_pass_via_aligned_spf(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        fake_record = {
            "valid": True,
            "tags": {
                "p": {"value": "reject"},
                "aspf": {"value": "r"},
                "adkim": {"value": "r"},
            },
        }
        with patch("spf.check2", return_value=("pass", "ok")), patch(
            "checkdmarc.check_dmarc", return_value=fake_record
        ):
            result = _engine().verify(parsed)

        assert result.dmarc.record_found is True
        assert result.dmarc.policy == "reject"
        assert result.dmarc.spf_aligned is True
        assert result.dmarc.passed is True
        assert result.dmarc_failed is False

    def test_dmarc_fail_when_unaligned_and_unsigned(self):
        parsed = EmailParser().parse_bytes(SPOOFED_EML)
        fake_record = {
            "valid": True,
            "tags": {
                "p": {"value": "reject"},
                "aspf": {"value": "r"},
                "adkim": {"value": "r"},
            },
        }
        with patch("spf.check2", return_value=("fail", "no")), patch(
            "checkdmarc.check_dmarc", return_value=fake_record
        ):
            result = _engine().verify(parsed)

        assert result.dmarc.record_found is True
        assert result.dmarc.passed is False
        assert result.dmarc_failed is True

    def test_no_dmarc_record_is_not_a_crash(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        with patch(
            "checkdmarc.check_dmarc",
            return_value={"valid": False, "error": "NXDOMAIN"},
        ):
            result = _engine().verify(parsed)

        assert result.dmarc.checked is True
        assert result.dmarc.record_found is False
        assert result.dmarc_failed is False  # no record != failure, just unknown

    def test_dns_exception_degrades_gracefully(self):
        parsed = EmailParser().parse_bytes(ALIGNED_EML)
        with patch("checkdmarc.check_dmarc", side_effect=Exception("DNS timeout")):
            result = _engine().verify(parsed)  # must not raise

        assert result.dmarc.error == "DNS timeout"
        assert result.dmarc.record_found is False
