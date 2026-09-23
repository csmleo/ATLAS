"""
==============================================================================
 src/auth_validator.py — Email Authentication Validator (SPF / DKIM / DMARC)
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Performs both passive and active validation of email authentication protocols.

 Passive:  Reads the pre-stamped 'Authentication-Results' header injected
           by the receiving mail gateway.
 Active:   Performs real-time DNS queries to independently verify SPF
           and DMARC policy alignment.

 OUTPUT
 ------
 Returns an AuthResult dataclass with individual verdicts and a combined
 network-layer risk score (0-100).
==============================================================================
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

import dns.resolver
import dns.exception

from .email_parser import ParsedEmail

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    """
    Structured container for the combined SPF / DKIM / DMARC authentication
    analysis results. Includes both passive (header-read) and active (DNS)
    verdicts.
    """
    # --- Passive verdicts (from Authentication-Results header) ---
    spf_passive:   str   # 'pass', 'fail', 'softfail', 'neutral', 'none', 'unknown'
    dkim_passive:  str
    dmarc_passive: str
    dmarc_policy:  str   # 'none', 'quarantine', 'reject', 'unknown'

    # --- Active DNS verdicts ---
    spf_dns_record:   Optional[str]   # Raw TXT record retrieved
    dmarc_dns_record: Optional[str]

    # --- Cross-field mismatch indicators ---
    from_reply_to_mismatch: bool  # True if From domain != Reply-To domain
    from_return_path_mismatch: bool

    # --- Aggregated network risk score contribution (0-100) ---
    network_score: int
    network_findings: list[str]  # Human-readable list of findings for the report


# ---------------------------------------------------------------------------
# Passive Header Parsing
# ---------------------------------------------------------------------------

def _parse_auth_results_header(raw: Optional[str]) -> dict[str, str]:
    """
    Parses the 'Authentication-Results' header to extract individual
    SPF, DKIM, and DMARC verdict tokens.

    Returns:
        dict with keys 'spf', 'dkim', 'dmarc' and their verdict strings.
    """
    verdicts = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "dmarc_policy": "unknown"}

    if not raw:
        return verdicts

    raw_lower = raw.lower()

    # SPF verdict: match 'spf=<result>'
    spf_match = re.search(r"spf=(\S+)", raw_lower)
    if spf_match:
        verdicts["spf"] = spf_match.group(1).split(";")[0].split(" ")[0]

    # DKIM verdict: match 'dkim=<result>'
    dkim_match = re.search(r"dkim=(\S+)", raw_lower)
    if dkim_match:
        verdicts["dkim"] = dkim_match.group(1).split(";")[0].split(" ")[0]

    # DMARC verdict: match 'dmarc=<result>'
    dmarc_match = re.search(r"dmarc=(\S+)", raw_lower)
    if dmarc_match:
        verdicts["dmarc"] = dmarc_match.group(1).split(";")[0].split(" ")[0]

    # DMARC policy: match 'p=<policy>'
    policy_match = re.search(r"\(p=(\w+)\)", raw_lower)
    if policy_match:
        verdicts["dmarc_policy"] = policy_match.group(1)

    return verdicts


# ---------------------------------------------------------------------------
# Active DNS Validation
# ---------------------------------------------------------------------------

def _query_spf_record(domain: str) -> Optional[str]:
    """
    Queries DNS for the SPF TXT record of the given domain.
    Returns the raw SPF record string or None if not found.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
        for rdata in answers:
            record = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if record.startswith("v=spf1"):
                logger.info("[auth_validator] SPF record found for %s: %s", domain, record[:80])
                return record
    except dns.exception.DNSException as exc:
        logger.warning("[auth_validator] SPF DNS query failed for %s: %s", domain, exc)
    return None


def _query_dmarc_record(domain: str) -> Optional[str]:
    """
    Queries DNS for the DMARC TXT record at _dmarc.<domain>.
    Returns the raw DMARC record string or None if not found.
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5.0)
        for rdata in answers:
            record = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if "v=DMARC1" in record:
                logger.info("[auth_validator] DMARC record found: %s", record[:80])
                return record
    except dns.exception.DNSException as exc:
        logger.warning("[auth_validator] DMARC DNS query failed for %s: %s", dmarc_domain, exc)
    return None


def _extract_domain(address: str) -> str:
    """Extracts the domain part from an email address string."""
    if "@" in address:
        return address.split("@")[-1].strip().lower().rstrip(">")
    return address.strip().lower()


# ---------------------------------------------------------------------------
# Cross-Field Mismatch Detection
# ---------------------------------------------------------------------------

def _check_field_mismatches(parsed: ParsedEmail) -> tuple[bool, bool]:
    """
    Detects domain-level mismatches between:
    - From domain vs. Reply-To domain
    - From domain vs. Return-Path domain

    These discrepancies are a primary indicator of BEC and spoofing attacks.

    Returns:
        tuple: (from_reply_to_mismatch, from_return_path_mismatch)
    """
    from_domain = _extract_domain(parsed.from_address)

    reply_to_mismatch = False
    if parsed.reply_to:
        reply_domain = _extract_domain(parsed.reply_to)
        if reply_domain and reply_domain != from_domain:
            reply_to_mismatch = True
            logger.warning(
                "[auth_validator] From/Reply-To domain mismatch: '%s' vs '%s'",
                from_domain, reply_domain,
            )

    return_path_mismatch = False
    if parsed.return_path:
        rp_domain = _extract_domain(parsed.return_path)
        if rp_domain and rp_domain != from_domain:
            return_path_mismatch = True
            logger.warning(
                "[auth_validator] From/Return-Path domain mismatch: '%s' vs '%s'",
                from_domain, rp_domain,
            )

    return reply_to_mismatch, return_path_mismatch


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def _calculate_network_score(
    spf:    str,
    dkim:   str,
    dmarc:  str,
    dmarc_policy: str,
    reply_mismatch: bool,
    rp_mismatch: bool,
) -> tuple[int, list[str]]:
    """
    Calculates the Network Layer risk sub-score based on authentication
    verdicts and cross-field mismatches. Max contribution: 100 points.

    Returns:
        tuple: (integer score 0-100, list of human-readable findings)
    """
    score = 0
    findings: list[str] = []

    # SPF
    if spf in ("fail", "hardfail"):
        score += 20
        findings.append("❌ SPF: FAIL — sending IP not authorized by domain policy")
    elif spf == "softfail":
        score += 10
        findings.append("⚠️ SPF: SOFTFAIL — sending IP weakly rejected by domain policy")
    elif spf == "pass":
        findings.append("✅ SPF: PASS")
    else:
        findings.append(f"⚠️ SPF: {spf.upper()} — indeterminate result")

    # DKIM
    if dkim == "fail":
        score += 25
        findings.append("❌ DKIM: FAIL — cryptographic signature invalid or missing")
    elif dkim == "pass":
        findings.append("✅ DKIM: PASS — signature verified")
    else:
        findings.append(f"⚠️ DKIM: {dkim.upper()}")

    # DMARC
    if dmarc == "fail":
        score += 30
        findings.append(f"❌ DMARC: FAIL — alignment failure (policy: {dmarc_policy.upper()})")
        if dmarc_policy == "none":
            score += 10
            findings.append("⚠️ DMARC policy is 'none' — domain owner has no enforcement active")
    elif dmarc == "pass":
        findings.append("✅ DMARC: PASS — domain alignment verified")
    else:
        findings.append(f"⚠️ DMARC: {dmarc.upper()}")

    # Cross-field mismatches
    if reply_mismatch:
        score += 20
        findings.append("🚨 From/Reply-To domain mismatch — strong BEC indicator")
    if rp_mismatch:
        score += 15
        findings.append("🚨 From/Return-Path domain mismatch — bounce hijacking indicator")

    return min(score, 100), findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_authentication(parsed: ParsedEmail) -> AuthResult:
    """
    Performs a complete email authentication validation workflow:
    1. Parses the passive 'Authentication-Results' header from the gateway.
    2. Performs active DNS queries for SPF and DMARC records.
    3. Detects cross-field domain mismatches (BEC indicators).
    4. Calculates the network-layer risk sub-score.

    Args:
        parsed: A ParsedEmail object from email_parser.parse_eml().

    Returns:
        AuthResult: Fully populated authentication result container.
    """
    logger.info("[auth_validator] Starting authentication validation for: %s", parsed.from_address)

    # --- Step 1: Parse passive header ---
    passive = _parse_auth_results_header(parsed.authentication_results_raw)

    # --- Step 2: Active DNS queries ---
    from_domain = _extract_domain(parsed.from_address)
    spf_record   = _query_spf_record(from_domain)
    dmarc_record = _query_dmarc_record(from_domain)

    # --- Step 3: Cross-field mismatch detection ---
    reply_mismatch, rp_mismatch = _check_field_mismatches(parsed)

    # --- Step 4: Risk scoring ---
    net_score, findings = _calculate_network_score(
        spf=passive["spf"],
        dkim=passive["dkim"],
        dmarc=passive["dmarc"],
        dmarc_policy=passive["dmarc_policy"],
        reply_mismatch=reply_mismatch,
        rp_mismatch=rp_mismatch,
    )

    logger.info("[auth_validator] Network risk score: %d/100 | Findings: %d", net_score, len(findings))

    return AuthResult(
        spf_passive=passive["spf"],
        dkim_passive=passive["dkim"],
        dmarc_passive=passive["dmarc"],
        dmarc_policy=passive["dmarc_policy"],
        spf_dns_record=spf_record,
        dmarc_dns_record=dmarc_record,
        from_reply_to_mismatch=reply_mismatch,
        from_return_path_mismatch=rp_mismatch,
        network_score=net_score,
        network_findings=findings,
    )
