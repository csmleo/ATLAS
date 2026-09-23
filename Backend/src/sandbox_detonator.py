"""
==============================================================================
 src/sandbox_detonator.py — Dynamic Sandbox Detonation & OSINT Engine
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Submits suspicious URLs to URLScan.io for dynamic sandbox detonation.
 Uses an asynchronous polling pattern to wait for the scan to complete,
 then retrieves the screenshot, verdict, and redirect chain as evidence.

 Also queries VirusTotal for hash-based reputation of attachments and URLs.

 OUTPUT
 ------
 Returns a SandboxResult dataclass with verdicts, screenshot path, and
 a dynamic risk sub-score for the final SOAR scoring pipeline.
==============================================================================
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
_URLSCAN_SCREENSHOT  = "https://urlscan.io/screenshots/{uuid}.png"

_VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{id}"
_VT_HASH_REPORT = "https://www.virustotal.com/api/v3/files/{hash}"

_POLL_INITIAL_WAIT_S = 15    # Initial wait before first poll (URLScan needs time to render)
_POLL_INTERVAL_S     = 5     # Interval between subsequent polls
_POLL_MAX_ATTEMPTS   = 20    # Maximum polling attempts before timeout


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class UrlScanResult:
    """Result from a single URLScan.io detonation."""
    url: str
    scan_uuid: Optional[str]
    verdict_malicious: bool
    verdict_score: int              # URLScan's own score 0-100
    screenshot_path: Optional[str]  # Local path where screenshot was saved
    redirect_chain: list[str]       # List of redirect URLs traversed
    page_domain: Optional[str]
    page_title: Optional[str]
    error: Optional[str]            # Set if the detonation failed


@dataclass
class VtHashResult:
    """Result from a VirusTotal file hash reputation query."""
    sha256: str
    filename: str
    detection_count: int
    total_engines: int
    verdict: str    # 'clean', 'suspicious', 'malicious', 'unknown'


@dataclass
class SandboxResult:
    """
    Aggregated container for all dynamic analysis results.
    """
    url_scan_results: list[UrlScanResult]
    vt_hash_results: list[VtHashResult]
    dynamic_score: int
    dynamic_findings: list[str]
    screenshots_downloaded: list[str]


# ---------------------------------------------------------------------------
# URLScan.io Integration
# ---------------------------------------------------------------------------

def _submit_url_to_urlscan(url: str, api_key: str) -> Optional[str]:
    """
    Submits a URL to URLScan.io for detonation.
    Uses 'unlisted' visibility to avoid publicly indexing the scan,
    which would risk alerting the attacker that the URL is being inspected.

    Returns:
        str: The scan UUID for subsequent polling, or None on failure.
    """
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "url": url,
        "visibility": "unlisted",
        "tags": ["phishing-eml-analyzer", "automated-forensics"],
    }
    try:
        resp = requests.post(_URLSCAN_SUBMIT_URL, headers=headers, json=payload, timeout=15)
        if resp.status_code == 200:
            scan_uuid = resp.json().get("uuid")
            logger.info("[sandbox] URLScan submitted: %s → UUID: %s", url, scan_uuid)
            return scan_uuid
        else:
            logger.warning("[sandbox] URLScan submit failed (HTTP %d): %s", resp.status_code, resp.text[:200])
    except requests.RequestException as exc:
        logger.error("[sandbox] URLScan submit error: %s", exc)
    return None


def _poll_urlscan_result(scan_uuid: str, api_key: str) -> Optional[dict]:
    """
    Polls URLScan.io for the analysis result using the scan UUID.
    Implements an initial wait followed by interval-based polling to
    avoid hammering the API before the page has been rendered.

    Returns:
        dict: The raw result JSON or None if timeout/error occurred.
    """
    logger.info("[sandbox] Waiting %ds before first poll for UUID: %s", _POLL_INITIAL_WAIT_S, scan_uuid)
    time.sleep(_POLL_INITIAL_WAIT_S)

    headers = {"API-Key": api_key}
    result_url = _URLSCAN_RESULT_URL.format(uuid=scan_uuid)

    for attempt in range(1, _POLL_MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(result_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                logger.info("[sandbox] Poll attempt %d/%d — result ready.", attempt, _POLL_MAX_ATTEMPTS)
                return resp.json()
            elif resp.status_code == 404:
                logger.debug("[sandbox] Poll attempt %d/%d — scan not ready yet.", attempt, _POLL_MAX_ATTEMPTS)
            else:
                logger.warning("[sandbox] Poll attempt %d returned HTTP %d.", attempt, resp.status_code)
        except requests.RequestException as exc:
            logger.warning("[sandbox] Poll attempt %d error: %s", attempt, exc)

        time.sleep(_POLL_INTERVAL_S)

    logger.error("[sandbox] Polling timed out for UUID: %s", scan_uuid)
    return None


def _download_screenshot(scan_uuid: str, url: str, output_dir: Path) -> Optional[str]:
    """
    Downloads the page screenshot from URLScan.io and saves it to the
    local screenshots directory with a safe, timestamped filename.

    Returns:
        str: Local filesystem path to the saved screenshot, or None.
    """
    screenshot_url = _URLSCAN_SCREENSHOT.format(uuid=scan_uuid)
    try:
        resp = requests.get(screenshot_url, timeout=20)
        if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("image"):
            # Build a safe filename from the URL domain
            from urllib.parse import urlparse
            domain_slug = urlparse(url).netloc.replace(".", "_").replace(":", "_")[:40]
            filename = output_dir / f"screenshot_{domain_slug}_{scan_uuid[:8]}.png"
            filename.write_bytes(resp.content)
            logger.info("[sandbox] Screenshot saved: %s", filename)
            return str(filename)
        else:
            logger.warning("[sandbox] Screenshot not available for UUID: %s", scan_uuid)
    except requests.RequestException as exc:
        logger.error("[sandbox] Screenshot download failed: %s", exc)
    return None


def _parse_urlscan_result(raw: dict, url: str, api_key: str, screenshots_dir: Path) -> UrlScanResult:
    """
    Extracts forensically relevant fields from the URLScan.io result JSON
    and downloads the page screenshot.
    """
    scan_uuid = raw.get("task", {}).get("uuid")
    verdict_data = raw.get("verdicts", {}).get("overall", {})
    verdict_malicious = verdict_data.get("malicious", False)
    verdict_score = verdict_data.get("score", 0)

    page = raw.get("page", {})
    page_domain = page.get("domain")
    page_title  = page.get("title", "")

    # Extract redirect chain from HTTP data
    redirects = []
    for req in raw.get("data", {}).get("requests", []):
        response = req.get("response", {}).get("response", {})
        if response.get("status") in (301, 302, 303, 307, 308):
            redirect_url = response.get("url") or req.get("request", {}).get("url", "")
            if redirect_url:
                redirects.append(redirect_url)

    # Download screenshot
    screenshot_path = None
    if scan_uuid:
        screenshot_path = _download_screenshot(scan_uuid, url, screenshots_dir)

    return UrlScanResult(
        url=url,
        scan_uuid=scan_uuid,
        verdict_malicious=verdict_malicious,
        verdict_score=verdict_score,
        screenshot_path=screenshot_path,
        redirect_chain=redirects,
        page_domain=page_domain,
        page_title=page_title,
        error=None,
    )


# ---------------------------------------------------------------------------
# VirusTotal Hash Reputation
# ---------------------------------------------------------------------------

def _query_vt_hash(sha256: str, filename: str, api_key: str) -> VtHashResult:
    """
    Queries the VirusTotal API v3 for file hash reputation.
    Requires a VirusTotal API key in the environment.
    """
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(_VT_HASH_REPORT.format(hash=sha256), headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            total      = sum(data.values())
            detections = malicious + suspicious
            verdict = "clean"
            if malicious > 5:
                verdict = "malicious"
            elif malicious > 0 or suspicious > 0:
                verdict = "suspicious"
            logger.info("[sandbox] VT Hash %s: %d/%d detections — %s", sha256[:16], detections, total, verdict)
            return VtHashResult(
                sha256=sha256, filename=filename,
                detection_count=detections, total_engines=total, verdict=verdict,
            )
        elif resp.status_code == 404:
            logger.info("[sandbox] VT Hash not found (first seen?): %s", sha256[:16])
            return VtHashResult(sha256=sha256, filename=filename, detection_count=0, total_engines=0, verdict="unknown")
        else:
            logger.warning("[sandbox] VT Hash query HTTP %d for %s", resp.status_code, sha256[:16])
    except requests.RequestException as exc:
        logger.error("[sandbox] VT Hash query error: %s", exc)

    return VtHashResult(sha256=sha256, filename=filename, detection_count=0, total_engines=0, verdict="unknown")


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def _calculate_dynamic_score(url_results: list[UrlScanResult], hash_results: list[VtHashResult]) -> tuple[int, list[str]]:
    """
    Calculates the Dynamic Layer risk sub-score based on sandbox and OSINT results.
    """
    score = 0
    findings: list[str] = []

    for res in url_results:
        if res.error:
            findings.append(f"⚠️ URL detonation failed for: {res.url[:80]} — {res.error}")
            continue

        if res.verdict_malicious:
            score += 50
            findings.append(f"🚨 URLScan MALICIOUS verdict for: {res.url[:80]} (score: {res.verdict_score})")
        elif res.verdict_score > 50:
            score += 25
            findings.append(f"⚠️ URLScan SUSPICIOUS verdict for: {res.url[:80]} (score: {res.verdict_score})")
        else:
            findings.append(f"✅ URLScan: {res.url[:80]} — no malicious verdict (score: {res.verdict_score})")

        if res.redirect_chain:
            score += 25
            findings.append(f"🔀 Redirect chain detected ({len(res.redirect_chain)} hops): {res.redirect_chain}")

        if res.screenshot_path:
            findings.append(f"📸 Screenshot captured: {res.screenshot_path}")

    for hr in hash_results:
        if hr.verdict == "malicious":
            score += 50
            findings.append(f"🚨 VirusTotal: '{hr.filename}' is MALICIOUS ({hr.detection_count}/{hr.total_engines})")
        elif hr.verdict == "suspicious":
            score += 15
            findings.append(f"⚠️ VirusTotal: '{hr.filename}' is SUSPICIOUS ({hr.detection_count}/{hr.total_engines})")
        elif hr.verdict == "unknown":
            findings.append(f"❓ VirusTotal: '{hr.filename}' SHA-256 not found (novel/unpublished sample)")
        else:
            findings.append(f"✅ VirusTotal: '{hr.filename}' is CLEAN ({hr.total_engines} engines)")

    if not url_results and not hash_results:
        findings.append("ℹ️ No URLs or attachments submitted to sandbox (no URLSCAN_API_KEY configured)")

    return min(score, 100), findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detonate(
    urls: list[str],
    attachments: list[dict],   # list of {'sha256': str, 'filename': str}
    screenshots_dir: str = "screenshots",
    urlscan_api_key: Optional[str] = None,
    vt_api_key: Optional[str] = None,
) -> SandboxResult:
    """
    Orchestrates the full dynamic sandbox detonation pipeline.

    1. Submits each URL to URLScan.io (skips if no API key configured).
    2. Polls URLScan.io for results and downloads screenshots.
    3. Queries VirusTotal for each attachment SHA-256 hash.
    4. Calculates the dynamic risk sub-score.

    Args:
        urls:             List of URL strings to detonate.
        attachments:      List of dicts with 'sha256' and 'filename' keys.
        screenshots_dir:  Directory path to save downloaded screenshots.
        urlscan_api_key:  URLScan.io API key (reads URLSCAN_API_KEY env var).
        vt_api_key:       VirusTotal API key (reads VT_API_KEY env var).

    Returns:
        SandboxResult: Aggregated sandbox and OSINT analysis results.
    """
    resolved_urlscan = urlscan_api_key or os.environ.get("URLSCAN_API_KEY", "")
    resolved_vt      = vt_api_key      or os.environ.get("VT_API_KEY", "")

    screenshots_path = Path(screenshots_dir)
    screenshots_path.mkdir(parents=True, exist_ok=True)

    url_results:  list[UrlScanResult]  = []
    hash_results: list[VtHashResult]   = []
    all_screenshots: list[str]         = []

    # --- URLScan.io detonation ---
    if resolved_urlscan and urls:
        for url in urls[:5]:    # Limit to 5 URLs per run to respect API rate limits
            scan_uuid = _submit_url_to_urlscan(url, resolved_urlscan)
            if not scan_uuid:
                url_results.append(UrlScanResult(
                    url=url, scan_uuid=None, verdict_malicious=False, verdict_score=0,
                    screenshot_path=None, redirect_chain=[], page_domain=None,
                    page_title=None, error="Submission failed",
                ))
                continue

            raw = _poll_urlscan_result(scan_uuid, resolved_urlscan)
            if raw:
                result = _parse_urlscan_result(raw, url, resolved_urlscan, screenshots_path)
                if result.screenshot_path:
                    all_screenshots.append(result.screenshot_path)
                url_results.append(result)
            else:
                url_results.append(UrlScanResult(
                    url=url, scan_uuid=scan_uuid, verdict_malicious=False, verdict_score=0,
                    screenshot_path=None, redirect_chain=[], page_domain=None,
                    page_title=None, error="Polling timed out",
                ))
    else:
        if not resolved_urlscan:
            logger.info("[sandbox] URLSCAN_API_KEY not set — skipping URL detonation.")

    # --- VirusTotal hash reputation ---
    if resolved_vt and attachments:
        for att in attachments:
            result = _query_vt_hash(att["sha256"], att["filename"], resolved_vt)
            hash_results.append(result)
    else:
        if not resolved_vt:
            logger.info("[sandbox] VT_API_KEY not set — skipping hash reputation queries.")

    # --- Scoring ---
    dyn_score, findings = _calculate_dynamic_score(url_results, hash_results)

    logger.info("[sandbox] Dynamic score: %d/100 | URL scans: %d | Hash checks: %d",
                dyn_score, len(url_results), len(hash_results))

    return SandboxResult(
        url_scan_results=url_results,
        vt_hash_results=hash_results,
        dynamic_score=dyn_score,
        dynamic_findings=findings,
        screenshots_downloaded=all_screenshots,
    )
