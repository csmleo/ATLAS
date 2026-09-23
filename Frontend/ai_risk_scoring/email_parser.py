"""Parse RFC 5322 (.eml) messages into ATLAS risk-engine evidence."""

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Union

from risk_engine import analyze_email


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
URGENT_TERMS = (
    "urgent", "immediately", "action required", "verify your account",
    "suspended", "final notice", "password expires",
)
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs",
    ".vbe", ".ps1", ".scr", ".msi", ".jar", ".iso", ".img", ".lnk",
}


def _header_failed(message, mechanism: str) -> bool:
    """Detect a failed SPF, DKIM, or DMARC result from common mail headers."""
    mechanism = mechanism.lower()
    authentication_results = " ".join(message.get_all("Authentication-Results", []))
    if re.search(rf"\b{re.escape(mechanism)}\s*=\s*fail(?:ed)?\b", authentication_results, re.I):
        return True
    if mechanism == "spf":
        return any(re.search(r"\bfail\b", value, re.I) for value in message.get_all("Received-SPF", []))
    return False


def _message_body(message) -> str:
    """Extract readable text without treating attachments as email body."""
    parts = message.walk() if message.is_multipart() else [message]
    body_parts = []
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_maintype() != "text":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = part.get_payload(decode=True) or b""
            content = content.decode("utf-8", errors="replace")
        body_parts.append(str(content))
    return "\n".join(body_parts)


def _extract_attachments(message):
    attachments = []
    for part in message.walk():
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            filename = filename or "unnamed_attachment"
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "extension": Path(filename).suffix.lower(),
            })
    return attachments


def parse_eml(source: Union[bytes, str, Path]):
    """Return extracted email data and the matching risk-engine evidence payload."""
    if isinstance(source, (str, Path)):
        raw_email = Path(source).read_bytes()
    else:
        raw_email = source
    if not isinstance(raw_email, bytes):
        raise TypeError("A .eml file must be supplied as bytes or a file path.")

    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    from_header = str(message.get("From", ""))
    reply_to_header = str(message.get("Reply-To", ""))
    from_address = parseaddr(from_header)[1]
    reply_to_address = parseaddr(reply_to_header)[1]
    body = _message_body(message)
    urls = list(dict.fromkeys(URL_PATTERN.findall(body)))
    attachments = _extract_attachments(message)

    from_domain = from_address.rsplit("@", 1)[-1].lower() if "@" in from_address else ""
    reply_to_domain = reply_to_address.rsplit("@", 1)[-1].lower() if "@" in reply_to_address else ""
    subject = str(message.get("Subject", ""))
    content_for_language_check = f"{subject}\n{body}".lower()

    authentication = {
        "spf": "fail" if _header_failed(message, "spf") else "pass_or_unavailable",
        "dkim": "fail" if _header_failed(message, "dkim") else "pass_or_unavailable",
        "dmarc": "fail" if _header_failed(message, "dmarc") else "pass_or_unavailable",
    }
    evidence = {
        "spf_failed": authentication["spf"] == "fail",
        "dkim_failed": authentication["dkim"] == "fail",
        "dmarc_failed": authentication["dmarc"] == "fail",
        # A Reply-To domain different from From is useful explainable evidence.
        "reply_to_mismatch": bool(reply_to_domain and from_domain and reply_to_domain != from_domain),
        "sender_mismatch": False,
        "malicious_ip": False,
        "suspicious_domain": False,
        "attachment_suspicious": any(item["extension"] in SUSPICIOUS_ATTACHMENT_EXTENSIONS for item in attachments),
        "urgent_language": any(term in content_for_language_check for term in URGENT_TERMS),
        "new_sender": False,
        "suspicious_url": False,
        "urls": urls,
    }
    extracted = {
        "from_address": from_address,
        "reply_to_address": reply_to_address,
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "authentication": authentication,
    }
    return extracted, evidence


def analyze_eml(source: Union[bytes, str, Path]):
    """Parse an email and pass its evidence and URLs to the existing risk engine."""
    extracted, evidence = parse_eml(source)
    return {"extracted_email": extracted, "risk": analyze_email(evidence)}
