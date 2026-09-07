from urllib.parse import urlparse


def calculate_risk(
    iocs,
    headers=None,
    authentication=None,
    routing=None,
    attachments=None,
    domain_intelligence=None,
    reputation=None,
):
    headers = headers or {}
    authentication = authentication or {}
    routing = routing or {}
    attachments = attachments or []
    domain_intelligence = domain_intelligence or {}
    reputation = reputation or {}

    score = 0
    reasons = []

    # ---------- SPF / DKIM / DMARC ----------

    if authentication.get("spf") == "fail":
        score += 25
        reasons.append("SPF authentication failed (+25)")

    if authentication.get("dkim") == "fail":
        score += 20
        reasons.append("DKIM signature validation failed (+20)")

    if authentication.get("dmarc") == "fail":
        score += 20
        reasons.append("DMARC authentication failed (+20)")

    # ---------- Return-Path mismatch ----------
    #
    # CHANGED: this used to recompute the from/return-path domain
    # comparison inline (duplicating logic also present in
    # email_parser.py). It now reads the single precomputed value from
    # email_parser.py's compute_return_path_mismatch(). True = mismatch,
    # False = confirmed match, None = couldn't be determined (missing
    # headers) — None is intentionally treated as "no penalty", not
    # "assume safe", since we simply don't have enough data either way.

    if authentication.get("return_path_mismatch") is True:
        score += 20
        reasons.append("Return-Path domain differs from sender (+20)")

    # ---------- URLs ----------

    urls = iocs.get("urls", [])

    if urls:
        url_points = min(len(urls) * 5, 15)
        score += url_points
        reasons.append(f"{len(urls)} URL(s) detected (+{url_points})")

    # ---------- Attachments ----------

    dangerous_extensions = {
        ".exe",
        ".scr",
        ".js",
        ".vbs",
        ".bat",
        ".cmd",
        ".ps1",
        ".jar",
        ".iso",
        ".dll",
        ".zip",
        ".rar",
    }

    for attachment in attachments:
        ext = (attachment.get("extension") or "").lower()

        if ext in dangerous_extensions:
            score += 15
            reasons.append(f"Dangerous attachment ({ext}) (+15)")

    # ---------- Domain Intelligence ----------
    #
    # CHANGED: age is now scored on a tiered scale using age_days
    # directly, instead of only the binary "recent_domain" status flag.
    # <30 days keeps its original +10 (not +15 — that was a mistake in
    # an earlier draft of this file that was caught and corrected before
    # ever being used). 30-90 and 90-365 day bands are new.

    for domain in domain_intelligence.get("domains", []):
        status = domain.get("status")
        age_days = domain.get("age_days")

        if status == "not_registered":
            score += 15
            reasons.append("Domain is not currently registered (+15)")
            continue

        if age_days is None:
            continue

        if age_days < 30:
            score += 10
            reasons.append(f"Recently registered domain, {age_days} day(s) old (+10)")
        elif age_days < 90:
            score += 5
            reasons.append(f"Domain registered {age_days} day(s) ago (+5)")
        elif age_days < 365:
            score += 2
            reasons.append(f"Domain registered {age_days} day(s) ago (+2)")

    # ---------- IP Intelligence ----------

    for ip in domain_intelligence.get("ips", []):
        if ip.get("hosting") is True:
            score += 10
            reasons.append("Origin IP belongs to a hosting provider (+10)")

        # NEW: AbuseIPDB was already being fetched and attached to each
        # IP (see intel_service.py), but nothing here ever read it — it
        # was informational only. This is the fix.
        abuse = ip.get("abuseipdb") or {}
        confidence = abuse.get("abuse_confidence_score")

        if isinstance(confidence, (int, float)):
            if confidence >= 90:
                score += 25
                reasons.append(f"AbuseIPDB confidence {confidence}% (+25)")
            elif confidence >= 70:
                score += 20
                reasons.append(f"AbuseIPDB confidence {confidence}% (+20)")
            elif confidence >= 40:
                score += 10
                reasons.append(f"AbuseIPDB confidence {confidence}% (+10)")
            elif confidence >= 1:
                score += 5
                reasons.append(f"AbuseIPDB confidence {confidence}% (+5)")

    # ---------- VirusTotal Reputation ----------

    for _, rep in reputation.items():
        vt = rep.get("virustotal", {})

        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        vt_reputation = vt.get("reputation", 0)

        if malicious > 0:
            points = min(25, malicious * 5)
            score += points
            reasons.append(f"VirusTotal detected malicious URL (+{points})")

        elif suspicious > 0:
            score += 10
            reasons.append("VirusTotal flagged URL as suspicious (+10)")

        # NEW: VT's own community reputation score is a separate signal
        # from the malicious/suspicious engine counts above — a URL can
        # have zero detections and still carry a negative reputation.
        # This was being fetched and returned in the API response, but
        # never scored.
        if isinstance(vt_reputation, (int, float)) and vt_reputation < 0:
            score += 10
            reasons.append(f"VirusTotal community reputation is negative ({vt_reputation}) (+10)")

    # ---------- URLhaus Reputation ----------

    for _, rep in reputation.items():
        uh = rep.get("urlhaus", {})

        if uh.get("status") == "malicious":
            score += 20
            reasons.append("URLhaus lists URL as malicious (+20)")

    # ---------- SMTP Routing ----------

    hop_count = routing.get("hop_count", 0)

    if hop_count == 1:
        score += 5
        reasons.append("Only one SMTP relay observed (+5)")

    # ---------- Clamp ----------

    score = max(0, min(score, 100))

    if score >= 80:
        verdict = "High Risk Phishing"
        confidence = 99
    elif score >= 60:
        verdict = "Suspicious"
        confidence = 92
    elif score >= 30:
        verdict = "Medium Risk"
        confidence = 80
    else:
        verdict = "Low Risk"
        confidence = 65

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
    }