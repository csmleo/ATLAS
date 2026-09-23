"""
==============================================================================
 src/static_extractor.py — Static IoC Extractor (URLs, Domains & SHA-256)
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Safely extracts all Indicators of Compromise (IoCs) from the email body
 and attachments without executing any content. Key operations:

 - Parses HTML body with BeautifulSoup4 to extract href URLs
 - Detects anchor text vs. href destination mismatches (phishing tell)
 - Extracts plain-text URLs with regex
 - Normalizes domains using tldextract
 - Attachment metadata is already in ParsedEmail.attachments (from parser)

 OUTPUT
 ------
 Returns an IoCExtractionResult dataclass with all extracted indicators.
==============================================================================
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

from .email_parser import ParsedEmail

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex pattern for URL extraction from plain text
_URL_PATTERN = re.compile(
    r"https?://[^\s\<\>\"\'\)\(\]\[\\]+"
)

# Suspicious TLDs commonly abused in phishing campaigns
_SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "icu", "club",
    "online", "site", "info", "click", "link", "ru", "cn", "pw",
}

# Known brands commonly impersonated in phishing
_IMPERSONATED_BRANDS = {
    "microsoft", "google", "paypal", "amazon", "apple", "fedex", "dhl",
    "netflix", "linkedin", "facebook", "instagram", "whatsapp", "dropbox",
    "docusign", "santander", "bbva", "caixabank", "bankia",
}


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class UrlIoC:
    """Represents a single extracted URL with forensic metadata."""
    url: str
    anchor_text: str            # Display text of the hyperlink (if from HTML)
    domain: str
    subdomain: str
    tld: str
    is_anchor_mismatch: bool    # True if anchor text contains a different domain than href
    is_suspicious_tld: bool
    is_brand_impersonation: bool
    source: str                 # 'html', 'plaintext'


@dataclass
class IoCExtractionResult:
    """
    Structured container for all static Indicators of Compromise
    extracted from the email body and attachments.
    """
    urls: list[UrlIoC]
    unique_domains: list[str]
    suspicious_url_count: int
    brand_impersonation_domains: list[str]
    anchor_mismatch_count: int
    ioc_findings: list[str]


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _extract_domain_parts(url: str) -> tuple[str, str, str]:
    """
    Uses tldextract to decompose a URL into (subdomain, domain, tld).
    Returns empty strings on failure.
    """
    try:
        ext = tldextract.extract(url)
        return ext.subdomain, ext.domain, ext.suffix
    except Exception:
        return "", "", ""


def _is_anchor_mismatch(anchor_text: str, href_domain: str) -> bool:
    """
    Detects if the visible anchor text contains a URL pointing to a
    different domain than the actual href destination.

    Example of a mismatch:
        Visible: 'Click here to login to microsoft.com'
        Href:    'https://phish-site.xyz/steal-creds'
    """
    if not anchor_text or not href_domain:
        return False
    # Check if any known brand or domain keyword appears in anchor text
    anchor_lower = anchor_text.lower()
    for brand in _IMPERSONATED_BRANDS:
        if brand in anchor_lower and brand not in href_domain.lower():
            return True
    # Also check if the anchor looks like a URL pointing to a different domain
    anchor_url_match = _URL_PATTERN.search(anchor_text)
    if anchor_url_match:
        anchor_domain = _extract_domain_parts(anchor_url_match.group(0))[1]
        if anchor_domain and anchor_domain != href_domain:
            return True
    return False


def _is_brand_impersonation(domain: str) -> bool:
    """Returns True if the domain contains a known brand name as a substring."""
    domain_lower = domain.lower()
    return any(brand in domain_lower for brand in _IMPERSONATED_BRANDS)


def _build_url_ioc(url: str, anchor_text: str = "", source: str = "plaintext") -> UrlIoC:
    """Constructs a fully annotated UrlIoC object from a raw URL string."""
    subdomain, domain, tld = _extract_domain_parts(url)
    href_mismatch = _anchor_mismatch = _is_anchor_mismatch(anchor_text, domain)

    return UrlIoC(
        url=url.strip(),
        anchor_text=anchor_text.strip(),
        domain=domain,
        subdomain=subdomain,
        tld=tld,
        is_anchor_mismatch=href_mismatch,
        is_suspicious_tld=tld.lower() in _SUSPICIOUS_TLDS,
        is_brand_impersonation=_is_brand_impersonation(domain),
        source=source,
    )


# ---------------------------------------------------------------------------
# Extraction Functions
# ---------------------------------------------------------------------------

def _extract_html_urls(html_body: str) -> list[UrlIoC]:
    """
    Parses the HTML body using BeautifulSoup4 to extract all <a href>
    hyperlinks, capturing both the destination URL and visible anchor text.
    """
    if not html_body.strip():
        return []

    iocs: list[UrlIoC] = []
    seen_urls: set[str] = set()

    try:
        soup = BeautifulSoup(html_body, "lxml")
        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "").strip()
            if not href.startswith("http"):
                continue
            if href in seen_urls:
                continue
            seen_urls.add(href)
            anchor_text = tag.get_text(strip=True)
            iocs.append(_build_url_ioc(href, anchor_text=anchor_text, source="html"))
    except Exception as exc:
        logger.warning("[static_extractor] HTML parsing error: %s", exc)

    return iocs


def _extract_plaintext_urls(plain_body: str) -> list[UrlIoC]:
    """
    Extracts URLs from the plain-text body using regex. These URLs lack
    anchor text context, so mismatch detection does not apply.
    """
    if not plain_body.strip():
        return []

    iocs: list[UrlIoC] = []
    seen_urls: set[str] = set()

    for match in _URL_PATTERN.finditer(plain_body):
        url = match.group(0).rstrip(".,;)")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        iocs.append(_build_url_ioc(url, source="plaintext"))

    return iocs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_iocs(parsed: ParsedEmail) -> IoCExtractionResult:
    """
    Performs complete static IoC extraction from an email's body content.

    Process:
    1. Extract URLs from HTML body (with anchor/href mismatch detection).
    2. Extract URLs from plain-text body.
    3. Deduplicate and annotate each URL with forensic metadata.
    4. Generate summary findings for the report.

    Args:
        parsed: A ParsedEmail object from email_parser.parse_eml().

    Returns:
        IoCExtractionResult: All extracted IoCs and associated analysis.
    """
    logger.info("[static_extractor] Starting static IoC extraction.")

    # --- URL Extraction ---
    html_urls = _extract_html_urls(parsed.body_html)
    plain_urls = _extract_plaintext_urls(parsed.body_plain)

    # Deduplicate: prefer HTML entries (richer metadata) over plain-text duplicates
    all_urls: list[UrlIoC] = []
    seen: set[str] = set()
    for ioc in html_urls + plain_urls:
        if ioc.url not in seen:
            seen.add(ioc.url)
            all_urls.append(ioc)

    # --- Aggregated statistics ---
    unique_domains = list({ioc.domain for ioc in all_urls if ioc.domain})
    suspicious = [u for u in all_urls if u.is_suspicious_tld or u.is_brand_impersonation]
    brand_impersonation_domains = list({u.domain for u in all_urls if u.is_brand_impersonation})
    anchor_mismatches = [u for u in all_urls if u.is_anchor_mismatch]

    # --- Build findings ---
    findings: list[str] = []
    findings.append(f"🔗 Total URLs extracted: {len(all_urls)} ({len(html_urls)} HTML, {len(plain_urls)} plain-text)")
    findings.append(f"🌐 Unique domains: {len(unique_domains)}")

    if anchor_mismatches:
        findings.append(
            f"🚨 Anchor text / href mismatches detected: {len(anchor_mismatches)} — "
            "link destination hidden behind legitimate-looking text"
        )
    if brand_impersonation_domains:
        findings.append(
            f"🚨 Brand impersonation detected in domains: {', '.join(brand_impersonation_domains)}"
        )
    if suspicious:
        findings.append(f"⚠️ Suspicious TLD or brand impersonation URLs: {len(suspicious)}")
    if parsed.attachments:
        findings.append(f"📎 Attachments found: {len(parsed.attachments)}")
        for att in parsed.attachments:
            findings.append(
                f"  • {att.filename} [{att.content_type}] "
                f"— {att.size_bytes} bytes — SHA-256: `{att.sha256}`"
            )

    logger.info(
        "[static_extractor] Extraction complete — URLs: %d | Domains: %d | Suspicious: %d",
        len(all_urls), len(unique_domains), len(suspicious),
    )

    return IoCExtractionResult(
        urls=all_urls,
        unique_domains=unique_domains,
        suspicious_url_count=len(suspicious),
        brand_impersonation_domains=brand_impersonation_domains,
        anchor_mismatch_count=len(anchor_mismatches),
        ioc_findings=findings,
    )
