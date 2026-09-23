"""
==============================================================================
 src/network_forensics.py — Network Forensics & Hop Trace Engine
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Traces the complete network path of an email by parsing all 'Received:'
 headers in chronological order (origin → destination). Identifies the
 true public IP origin by filtering out private RFC 1918 address ranges.

 OUTPUT
 ------
 Returns a NetworkForensicsResult with the IP hop trace and origin IP.
==============================================================================
"""

from __future__ import annotations

import email.utils
from email.utils import parsedate_to_datetime
from datetime import datetime
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from .email_parser import ParsedEmail

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex to extract IPv4 addresses from Received header strings
_IPV4_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# RFC 1918 private and reserved address blocks to filter out
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
]


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class HopInfo:
    """Represents a single relay hop extracted from a 'Received:' header."""
    hop_index: int
    raw_header: str
    ip_addresses: list[str]     # All IPs found in this hop
    first_public_ip: Optional[str]  # First non-private IP in this hop
    from_host: str = "Unknown"
    by_host: str = "Unknown"
    protocol: str = "SMTP"
    primary_ip: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    delay_seconds: Optional[float] = None
    delay_formatted: str = "Delay unavailable"
    is_origin_candidate: bool = False
    is_private: bool = True


@dataclass
class NetworkForensicsResult:
    """
    Structured container for the complete network path analysis of an email.
    """
    hops: list[HopInfo]
    origin_ip: Optional[str]       # True public origin IP (first public IP in chain)
    total_hops: int
    has_anomalous_hops: bool       # True if hop count is suspiciously high (> 6)
    hop_findings: list[str]        # Human-readable findings for the report


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _is_private_ip(ip_str: str) -> bool:
    """
    Returns True if the given IP address falls within a private,
    loopback, or otherwise non-routable range (RFC 1918 / RFC 5735).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _extract_ips_from_hop(raw_header: str) -> list[str]:
    """
    Extracts all IPv4 addresses from a single raw 'Received:' header string.
    Returns them in the order they appear.
    """
    return _IPV4_PATTERN.findall(raw_header)


def _find_first_public_ip(ips: list[str]) -> Optional[str]:
    """Returns the first non-private IP from a list of IP strings."""
    for ip in ips:
        if not _is_private_ip(ip):
            return ip
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def trace_network_hops(parsed: ParsedEmail) -> NetworkForensicsResult:
    """
    Traces the full network relay path from the raw 'Received:' headers.

    The received_hops list in ParsedEmail is already in chronological order
    (oldest/origin first) as reversed by email_parser.py.

    Process:
    1. Parse each hop to extract all IP addresses and routing details.
    2. Extract and parse timestamps to calculate hop-to-hop transit delays.
    3. Identify the first hop that contains a publicly routable IP (origin candidate).
    4. Flag anomalies (excessive hops, suspicious relays).

    Args:
        parsed: A ParsedEmail object from email_parser.parse_eml().

    Returns:
        NetworkForensicsResult: Complete hop trace analysis.
    """
    logger.info("[network_forensics] Tracing %d received hops.", len(parsed.received_hops))

    hops: list[HopInfo] = []
    origin_ip: Optional[str] = None
    origin_candidate_found = False
    prev_dt: Optional[datetime] = None

    for idx, raw_hop in enumerate(parsed.received_hops):
        # 1. Parse header sections and date
        parts = raw_hop.rsplit(";", 1)
        date_str = parts[1].strip() if len(parts) > 1 else None
        body = parts[0].replace("\n", " ").strip()

        # 2. Extract from / by / with protocol
        from_match = re.search(r"from\s+([^\s\(]+(?:\s*\([^\)]+\))?)", body, re.IGNORECASE)
        from_host = from_match.group(1).strip() if from_match else "Unknown"

        by_match = re.search(r"by\s+([^\s\(]+(?:\s*\([^\)]+\))?)", body, re.IGNORECASE)
        by_host = by_match.group(1).strip() if by_match else "Unknown"

        proto_match = re.search(r"with\s+([A-Za-z0-9_\-]+)", body, re.IGNORECASE)
        protocol = proto_match.group(1).upper() if proto_match else "SMTP"

        # 3. Extract IPs
        ips = _extract_ips_from_hop(raw_hop)
        public_ip = _find_first_public_ip(ips)
        primary_ip = ips[0] if ips else None

        # 4. Parse timestamp
        dt: Optional[datetime] = None
        if date_str:
            try:
                dt = parsedate_to_datetime(date_str)
            except Exception:
                dt = None

        # 5. Calculate transit delay between hops
        delay_seconds: Optional[float] = None
        delay_formatted = "Delay unavailable"
        if dt and prev_dt:
            diff = (dt - prev_dt).total_seconds()
            if diff >= 0:
                delay_seconds = diff
                if diff < 60:
                    delay_formatted = f"+{diff:.1f}s"
                else:
                    mins = int(diff // 60)
                    secs = diff % 60
                    delay_formatted = f"+{mins}m {secs:.1f}s"
            else:
                delay_formatted = f"{diff:.1f}s (Clock Skew)"
        elif idx == 0:
            delay_formatted = "Initial hop"

        if dt:
            prev_dt = dt

        # 6. Check origin candidate
        is_origin = False
        if public_ip and not origin_candidate_found:
            is_origin = True
            origin_candidate_found = True
            origin_ip = public_ip
            logger.info("[network_forensics] Origin public IP identified: %s (hop %d)", public_ip, idx)

        is_priv = _is_private_ip(primary_ip) if primary_ip else True

        hops.append(HopInfo(
            hop_index=idx,
            raw_header=raw_hop,
            ip_addresses=ips,
            first_public_ip=public_ip,
            from_host=from_host,
            by_host=by_host,
            protocol=protocol,
            primary_ip=primary_ip,
            timestamp_raw=date_str,
            timestamp_iso=dt.isoformat() if dt else None,
            delay_seconds=delay_seconds,
            delay_formatted=delay_formatted,
            is_origin_candidate=is_origin,
            is_private=is_priv,
        ))

    # --- Anomaly detection ---
    findings: list[str] = []
    has_anomalous = False

    if origin_ip:
        findings.append(f"🔎 True origin IP (first public): **{origin_ip}**")
    else:
        findings.append("⚠️ No public IP found in Received headers — all hops are private/internal")

    findings.append(f"📡 Total relay hops: {len(hops)}")

    if len(hops) > 6:
        has_anomalous = True
        findings.append(
            f"🚨 Suspicious hop count ({len(hops)}) — excessively long relay chain may indicate laundering"
        )

    if not hops:
        findings.append("⚠️ No 'Received:' headers found — direct injection or header stripping suspected")

    logger.info(
        "[network_forensics] Trace complete — Origin: %s | Hops: %d | Anomalous: %s",
        origin_ip, len(hops), has_anomalous,
    )

    return NetworkForensicsResult(
        hops=hops,
        origin_ip=origin_ip,
        total_hops=len(hops),
        has_anomalous_hops=has_anomalous,
        hop_findings=findings,
    )
