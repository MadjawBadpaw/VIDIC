from email import policy
from email.parser import BytesParser

from app.utils.ioc_extractor import extract_iocs, sha256_bytes


def parse_email(raw_email: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():

            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""

                attachments.append({
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                    "sha256": sha256_bytes(payload)
                })

            elif part.get_content_type() == "text/plain":
                body += part.get_content()

            elif part.get_content_type() == "text/html":
                body += part.get_content()

    else:
        body = msg.get_content()

    return {
        "headers": {
            "subject": msg.get("Subject"),
            "from": msg.get("From"),
            "to": msg.get("To"),
            "date": msg.get("Date"),
            "message_id": msg.get("Message-ID"),
            "return_path": msg.get("Return-Path"),
            "spf": msg.get("Received-SPF"),
            "dkim": msg.get("DKIM-Signature"),
        },
        "body_preview": body[:600],
        "body_length": len(body),
        "attachments": attachments,
        "iocs": extract_iocs(body),
    }