"""
==============================================================================
 src/email_parser.py — RFC 5322 Forensic Email Parser
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Parses a raw .eml file strictly following RFC 5322, extracting all
 forensically relevant header fields and MIME structure metadata.
 Surfaces any structural defects that may indicate evasion attempts.

 OUTPUT
 ------
 Returns a ParsedEmail dataclass consumed by all downstream modules.
==============================================================================
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import logging
import os
import quopri
import base64
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_file
from email.message import Message
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class AttachmentInfo:
    """Represents a single MIME attachment extracted from the email."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    content_transfer_encoding: str


@dataclass
class ParsedEmail:
    """
    Structured container for all forensically relevant fields extracted
    from a raw .eml file. Passed as the primary data object through the
    entire analysis pipeline.
    """
    # --- File metadata ---
    source_path: str
    source_sha256: str          # Integrity hash of the original .eml file

    # --- Core header fields ---
    message_id: str
    subject: str
    date_raw: str
    date_utc: Optional[datetime]

    # --- Sender / recipient fields ---
    from_address: str
    from_display_name: str
    to_addresses: list[str]
    reply_to: Optional[str]
    return_path: Optional[str]

    # --- Authentication pre-stamp (gateway verdict) ---
    authentication_results_raw: Optional[str]

    # --- Received hops (oldest → newest — i.e., reversed from raw) ---
    received_hops: list[str]

    # --- Body text ---
    body_plain: str
    body_html: str

    # --- Attachments ---
    attachments: list[AttachmentInfo] = field(default_factory=list)

    # --- MIME structural anomalies ---
    defects: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    """
    Calculates the SHA-256 hash of a file using chunked reading to
    avoid loading large files fully into memory.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    """Calculates the SHA-256 hash of a raw bytes object."""
    return hashlib.sha256(data).hexdigest()


def _decode_mime_words(value: Optional[str]) -> str:
    """
    Decodes RFC 2047 encoded-word syntax (=?charset?encoding?text?=)
    commonly used in Subject and From display names.
    """
    if not value:
        return ""
    from email.header import decode_header
    parts = decode_header(value)
    decoded = []
    for text, charset in parts:
        if isinstance(text, bytes):
            charset = charset or "utf-8"
            try:
                decoded.append(text.decode(charset, errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(text.decode("utf-8", errors="replace"))
        else:
            decoded.append(text)
    return "".join(decoded)


def _extract_body_parts(msg: Message) -> tuple[str, str]:
    """
    Recursively walks the MIME tree to extract the plaintext and HTML
    body parts. Handles quoted-printable and base64 encodings.

    Returns:
        tuple: (plain_text_body, html_body)
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        ct = part.get_content_type()
        cte = part.get("Content-Transfer-Encoding", "").lower()
        disposition = str(part.get("Content-Disposition", ""))

        # Skip attachments — handled separately
        if "attachment" in disposition:
            continue

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", errors="replace")

        if ct == "text/plain":
            plain_parts.append(text)
        elif ct == "text/html":
            html_parts.append(text)

    return "\n".join(plain_parts), "\n".join(html_parts)


def _extract_attachments(msg: Message) -> list[AttachmentInfo]:
    """
    Iterates MIME parts to find all attachments and extract their
    forensic metadata including SHA-256 hash and size.
    """
    attachments: list[AttachmentInfo] = []

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in disposition:
            continue

        filename = part.get_filename() or "unnamed_attachment"
        filename = _decode_mime_words(filename)
        content_type = part.get_content_type()
        cte = part.get("Content-Transfer-Encoding", "identity")

        payload = part.get_payload(decode=True)
        if payload is None:
            logger.warning("[email_parser] Attachment '%s' had no decodable payload.", filename)
            continue

        attachments.append(AttachmentInfo(
            filename=filename,
            content_type=content_type,
            size_bytes=len(payload),
            sha256=_sha256_bytes(payload),
            content_transfer_encoding=cte,
        ))

    return attachments


def _extract_addresses(raw: Optional[str]) -> list[str]:
    """Parses a comma-separated address field into a clean list."""
    if not raw:
        return []
    from email.utils import getaddresses
    return [addr for _, addr in getaddresses([raw]) if addr]


def _extract_received_hops(msg: Message) -> list[str]:
    """
    Extracts all 'Received:' headers and returns them in chronological
    order (oldest first, i.e., reversed from the raw email order).
    """
    hops = msg.get_all("Received") or []
    # Raw order is newest first; reverse to get the path from origin to destination
    return list(reversed([h.strip() for h in hops]))


def _parse_date(raw_date: str) -> Optional[datetime]:
    """Parses the raw Date header string into a UTC-aware datetime object."""
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(raw_date)
    except Exception:
        logger.warning("[email_parser] Could not parse date: '%s'", raw_date)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_eml(eml_path: str) -> ParsedEmail:
    """
    Parses a raw .eml file and returns a fully populated ParsedEmail object.

    Args:
        eml_path: Absolute path to the .eml file.

    Returns:
        ParsedEmail: Structured forensic data extracted from the email.

    Raises:
        FileNotFoundError: If the provided path does not exist.
        ValueError: If the file cannot be parsed as a valid email.
    """
    path = Path(eml_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"EML file not found: {path}")

    logger.info("[email_parser] Parsing: %s", path)

    # --- Integrity hash of the original file (must be first, before any modification) ---
    source_sha256 = _sha256_file(path)

    # --- Load and parse the email ---
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        msg: Message = message_from_file(fh, policy=email.policy.compat32)

    # --- Extract structural defects (MIME evasion indicators) ---
    defects = [str(d) for d in msg.defects]
    for part in msg.walk():
        defects.extend(str(d) for d in part.defects)

    # --- Extract sender fields ---
    from_raw = msg.get("From", "")
    from email.utils import parseaddr
    from_display_name, from_address = parseaddr(from_raw)
    from_display_name = _decode_mime_words(from_display_name)

    # --- Extract body ---
    body_plain, body_html = _extract_body_parts(msg)

    # --- Build the result ---
    result = ParsedEmail(
        source_path=str(path),
        source_sha256=source_sha256,
        message_id=msg.get("Message-ID", "").strip(),
        subject=_decode_mime_words(msg.get("Subject", "")),
        date_raw=msg.get("Date", ""),
        date_utc=_parse_date(msg.get("Date", "")),
        from_address=from_address,
        from_display_name=from_display_name,
        to_addresses=_extract_addresses(msg.get("To")),
        reply_to=msg.get("Reply-To", None),
        return_path=msg.get("Return-Path", None),
        authentication_results_raw=msg.get("Authentication-Results", None),
        received_hops=_extract_received_hops(msg),
        body_plain=body_plain,
        body_html=body_html,
        attachments=_extract_attachments(msg),
        defects=defects,
    )

    logger.info(
        "[email_parser] Parsed OK — Subject: '%s' | From: %s | Attachments: %d | Defects: %d",
        result.subject, result.from_address, len(result.attachments), len(result.defects),
    )

    return result
