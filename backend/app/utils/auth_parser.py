import re


def parse_authentication_results(header: str | None):
    """
    Parse Authentication-Results header into structured SPF/DKIM/DMARC values.

    Example header:
    mx.google.com;
        spf=fail smtp.mailfrom=evil.com;
        dkim=pass header.d=evil.com;
        dmarc=fail header.from=microsoft.com
    """

    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }

    if not header:
        return result

    patterns = {
        "spf": r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)",
        "dkim": r"dkim=(pass|fail|neutral|none|temperror|permerror)",
        "dmarc": r"dmarc=(pass|fail|bestguesspass|none|temperror|permerror)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, header, re.IGNORECASE)
        if match:
            result[key] = match.group(1).lower()

    return result