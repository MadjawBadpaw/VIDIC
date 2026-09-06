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

    return_path = authentication.get("return_path")
    sender = headers.get("from")

    if return_path and sender and "@" in sender:
        try:
            rp_domain = return_path.split("@")[-1].replace("<", "").replace(">", "")
            sender_domain = sender.split("@")[-1].replace("<", "").replace(">", "")

            if rp_domain.lower() != sender_domain.lower():
                score += 20
                reasons.append("Return-Path domain differs from sender (+20)")
        except Exception:
            pass

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

    for domain in domain_intelligence.get("domains", []):
        status = domain.get("status")

        if status == "not_registered":
            score += 15
            reasons.append("Domain is not currently registered (+15)")

        elif status == "recent_domain":
            score += 10
            reasons.append("Recently registered domain (+10)")

    # ---------- IP Intelligence ----------

    for ip in domain_intelligence.get("ips", []):
        if ip.get("hosting") is True:
            score += 10
            reasons.append("Origin IP belongs to a hosting provider (+10)")

    # ---------- VirusTotal Reputation ----------

    for _, rep in reputation.items():
        vt = rep.get("virustotal", {})

        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            points = min(25, malicious * 5)
            score += points
            reasons.append(f"VirusTotal detected malicious URL (+{points})")

        elif suspicious > 0:
            score += 10
            reasons.append("VirusTotal flagged URL as suspicious (+10)")

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