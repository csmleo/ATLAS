from pathlib import Path
from types import SimpleNamespace
import json
import logging
import re

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from src.email_parser import parse_eml
from src.auth_validator import validate_authentication
from src.network_forensics import trace_network_hops
from src.static_extractor import extract_iocs
from src.ai_analyzer import analyze_semantics
from src.sandbox_detonator import SandboxResult
from src.reporter import generate_report
from src.threat_intel import enrich_ip
from src.infrastructure_graph import build_graph

logger = logging.getLogger(__name__)

app = FastAPI(title="ATLAS Email Forensics API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("api_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR = Path("reportes")
REPORTS_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB max


EXAMPLES_DIR = Path("examples")

DEMO_SAMPLES_CATALOG = [
    {
        "id": "DEMO-PHISH-002",
        "filename": "DEMO-PHISH-002_m365_account_suspension.eml",
        "title": "Microsoft 365 Suspension Warning",
        "category": "Credential Harvesting / Brand Impersonation",
        "expected_verdict": "SUSPICIOUS (44/100)",
        "description": "Impersonates Microsoft account security with spoofed reply-to domain and credential harvesting link.",
    },
    {
        "id": "DEMO-BEC-001",
        "filename": "DEMO-BEC-001_ceo_wire_transfer.eml",
        "title": "Urgent CEO Wire Transfer Request",
        "category": "Business Email Compromise (BEC)",
        "expected_verdict": "SUSPICIOUS (46/100)",
        "description": "Executive impersonation requesting financial transaction via external anonymized relay.",
    },
    {
        "id": "DEMO-LEGIT-003",
        "filename": "DEMO-LEGIT-003_google_play_receipt.eml",
        "title": "Google Play Order Receipt",
        "category": "Legitimate Notification",
        "expected_verdict": "LEGITIMATE (4/100)",
        "description": "Authentic Google Play receipt with valid SPF/DKIM and cryptographic signatures.",
    },
]


def _run_forensic_pipeline(file_path: Path) -> dict:
    # 1. Forensic RFC 5322 Parsing
    parsed = parse_eml(str(file_path))

    # 2. Authentication Validation (SPF / DKIM / DMARC)
    auth = validate_authentication(parsed)

    # 3. Network Path Forensics (hops, origin IP, delays)
    net = trace_network_hops(parsed)

    # 4. Static IoC Extraction (URLs, domains, brand detection)
    iocs = extract_iocs(parsed)

    # 5. Semantic / Rule-based Analysis
    ai = analyze_semantics(
        from_address=parsed.from_address,
        subject=parsed.subject,
        body_plain=parsed.body_plain,
        body_html=parsed.body_html,
        provider="rule-based",
        lang="en",
    )

    # 6. Sandbox (Skipped in fast API prototype mode)
    sandbox = SandboxResult(
        url_scan_results=[],
        vt_hash_results=[],
        dynamic_score=0,
        dynamic_findings=["Dynamic sandbox detonation was not executed in this analysis pass."],
        screenshots_downloaded=[],
    )

    # 7. Final Verdict and Reports Generation
    verdict = generate_report(
        parsed=parsed,
        auth=auth,
        net=net,
        iocs=iocs,
        ai=ai,
        sandbox=sandbox,
        output_dir="reportes",
        lang="en",
    )

    # 8. Threat Intelligence Enrichment
    origin_ip = net.origin_ip or "Unknown"
    intel = enrich_ip(origin_ip)

    # Build indicators list for the threat intelligence table
    threat_indicators = []
    if origin_ip != "Unknown":
        threat_indicators.append({
            "indicator": origin_ip,
            "type": "IP address",
            "reputation": intel.get("reputation", "UNKNOWN"),
            "confidence": "90%",
            "source": "ATLAS Intelligence",
        })

    for domain in iocs.unique_domains:
        is_bad = domain in iocs.brand_impersonation_domains
        threat_indicators.append({
            "indicator": domain,
            "type": "Domain",
            "reputation": "Suspicious" if is_bad else "Analyzed",
            "confidence": "85%" if is_bad else "70%",
            "source": "ATLAS Static IOC Extractor",
        })

    for url_obj in iocs.urls:
        threat_indicators.append({
            "indicator": url_obj.url,
            "type": "URL",
            "reputation": "Malicious" if (url_obj.is_brand_impersonation or url_obj.is_suspicious_tld) else "Suspicious",
            "confidence": "88%",
            "source": "ATLAS Static IOC Extractor",
        })

    # Structured IOC table
    structured_iocs = []
    if origin_ip and origin_ip != "Unknown":
        structured_iocs.append({
            "type": "IP",
            "value": origin_ip,
            "source": "Received Header Relay",
            "confidence": "High (Observed)",
            "status": intel.get("reputation", "Observed"),
            "reason": "Identified as primary origin candidate in SMTP hop trace",
        })

    for domain in iocs.unique_domains:
        is_bad = domain in iocs.brand_impersonation_domains
        structured_iocs.append({
            "type": "Domain",
            "value": domain,
            "source": "Email Body / Header",
            "confidence": "High" if is_bad else "Medium",
            "status": "Suspicious" if is_bad else "Observed",
            "reason": "Brand impersonation heuristic triggered" if is_bad else "Domain extracted from message context",
        })

    for u in iocs.urls:
        reason = "Extracted body link"
        status = "Observed"
        if u.is_brand_impersonation:
            reason = "Brand impersonation target"
            status = "Malicious"
        elif u.is_anchor_mismatch:
            reason = "Anchor text mismatch (displayed text differs from link destination)"
            status = "Suspicious"
        elif u.is_suspicious_tld:
            reason = f"Suspicious top-level domain (.{u.tld})"
            status = "Suspicious"

        structured_iocs.append({
            "type": "URL",
            "value": u.url,
            "source": "HTML / Plain Body",
            "confidence": "High",
            "status": status,
            "reason": reason,
        })

    for att in parsed.attachments:
        structured_iocs.append({
            "type": "Attachment Hash",
            "value": att.sha256,
            "source": f"Attachment: {att.filename}",
            "confidence": "Definitive (SHA-256)",
            "status": "Analyzed",
            "reason": f"MIME attachment '{att.filename}' ({att.size_bytes} bytes, {att.content_type})",
        })

    # 9. Structured Relay Chain
    relay_chain = [
        {
            "hop_number": hop.hop_index + 1,
            "from_host": hop.from_host,
            "by_host": hop.by_host,
            "protocol": hop.protocol,
            "ip": hop.primary_ip,
            "all_ips": hop.ip_addresses,
            "first_public_ip": hop.first_public_ip,
            "timestamp_raw": hop.timestamp_raw,
            "timestamp_iso": hop.timestamp_iso,
            "delay_seconds": hop.delay_seconds,
            "delay_formatted": hop.delay_formatted,
            "is_origin_candidate": hop.is_origin_candidate,
            "is_private": hop.is_private,
            "raw_header": hop.raw_header,
        }
        for hop in net.hops
    ]

    # 10. Infrastructure Graph Generation
    primary_domain = iocs.unique_domains[0] if iocs.unique_domains else (
        parsed.from_address.split("@")[-1] if "@" in parsed.from_address else "unknown"
    )
    graph = build_graph(parsed.from_address, primary_domain, origin_ip, intel)

    graph_nodes = []
    for node, data in graph.nodes(data=True):
        graph_nodes.append({
            "id": str(node),
            "label": str(node),
            "type": data.get("type", "entity"),
        })

    graph_edges = []
    for u, v, data in graph.edges(data=True):
        graph_edges.append({
            "source": str(u),
            "target": str(v),
            "relationship": data.get("relationship", "associated"),
        })

    # Read generated report contents if available
    markdown_content = None
    if verdict.markdown_report_path and Path(verdict.markdown_report_path).exists():
        try:
            markdown_content = Path(verdict.markdown_report_path).read_text(encoding="utf-8")
        except Exception:
            pass

    json_content = None
    if verdict.json_report_path and Path(verdict.json_report_path).exists():
        try:
            json_content = json.loads(Path(verdict.json_report_path).read_text(encoding="utf-8"))
        except Exception:
            pass

    return {
        "incident_id": verdict.incident_id,
        "timestamp_utc": verdict.timestamp_utc,
        "source_file": verdict.source_file,
        "source_sha256": verdict.source_sha256,
        "global_score": verdict.global_score,
        "risk_label": verdict.risk_label,
        "network_score": verdict.network_score,
        "semantic_score": verdict.semantic_score,
        "dynamic_score": verdict.dynamic_score,
        "email_metadata": {
            "from": parsed.from_address,
            "from_display_name": parsed.from_display_name,
            "to": parsed.to_addresses,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "subject": parsed.subject,
            "message_id": parsed.message_id,
            "sending_ip": net.origin_ip,
            "date": parsed.date_raw,
            "total_hops": net.total_hops,
            "received_hops": [hop.raw_header for hop in net.hops],
            "attachments": [
                {
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size_bytes": att.size_bytes,
                    "sha256": att.sha256,
                    "content_transfer_encoding": att.content_transfer_encoding,
                }
                for att in parsed.attachments
            ],
        },
        "relay_chain": relay_chain,
        "authentication": {
            "spf": auth.spf_passive,
            "dkim": auth.dkim_passive,
            "dmarc": auth.dmarc_passive,
            "dmarc_policy": auth.dmarc_policy,
            "spf_dns_record": auth.spf_dns_record,
            "dmarc_dns_record": auth.dmarc_dns_record,
            "from_reply_to_mismatch": auth.from_reply_to_mismatch,
            "from_return_path_mismatch": auth.from_return_path_mismatch,
            "network_findings": auth.network_findings,
        },
        "iocs": {
            "urls": [
                {
                    "url": u.url,
                    "anchor_text": u.anchor_text,
                    "domain": u.domain,
                    "is_mismatch": u.is_anchor_mismatch,
                    "is_suspicious_tld": u.is_suspicious_tld,
                    "is_brand_impersonation": u.is_brand_impersonation,
                }
                for u in iocs.urls
            ],
            "unique_domains": iocs.unique_domains,
            "suspicious_url_count": iocs.suspicious_url_count,
            "brand_impersonation_domains": iocs.brand_impersonation_domains,
            "anchor_mismatch_count": iocs.anchor_mismatch_count,
            "ioc_findings": iocs.ioc_findings,
        },
        "structured_iocs": structured_iocs,
        "ai_analysis": {
            "provider": ai.provider,
            "model_used": ai.model_used,
            "urgency_level": ai.urgency_level,
            "executive_impersonation": ai.executive_impersonation,
            "credential_harvesting": ai.credential_harvesting,
            "financial_request": ai.financial_request,
            "brand_impersonation": ai.brand_impersonation,
            "detected_tactics": ai.detected_tactics,
            "narrative": ai.ai_narrative,
            "semantic_findings": ai.semantic_findings,
            "is_rule_based": ai.provider == "rule-based",
        },
        "threat_intel": {
            "is_demo": True,
            "disclaimer": "Threat intelligence and geolocation values shown here use a synthetic test dataset.",
            "ip": origin_ip,
            "country": intel.get("country", "Unknown"),
            "city": intel.get("city", "Unknown"),
            "asn": intel.get("asn", "Unknown"),
            "organization": intel.get("organization", "Unknown"),
            "reputation": intel.get("reputation", "UNKNOWN"),
            "sources": intel.get("sources", []),
            "indicators": threat_indicators,
        },
        "infrastructure_graph": {
            "disclaimer": "Infrastructure graph visualizes entity relationships. Correlation does not prove attacker attribution.",
            "nodes": graph_nodes,
            "edges": graph_edges,
        },
        "findings": {
            "all": verdict.all_findings,
            "network": verdict.network_findings,
            "semantic": verdict.semantic_findings,
            "dynamic": verdict.dynamic_findings,
        },
        "soar_tags": [
            {
                "tag": tag.tag,
                "priority": tag.priority,
                "sla_minutes": tag.sla_minutes,
                "color": tag.color,
            }
            for tag in verdict.soar_tags
        ],
        "reports": {
            "markdown_path": verdict.markdown_report_path,
            "json_path": verdict.json_report_path,
            "markdown_content": markdown_content,
            "json_content": json_content,
        },
    }


@app.get("/api/demo/samples")
def list_demo_samples():
    return DEMO_SAMPLES_CATALOG


@app.post("/api/demo/{sample_id}")
def analyze_demo_sample(sample_id: str):
    # Match by ID or filename
    matched = next((s for s in DEMO_SAMPLES_CATALOG if s["id"] == sample_id or s["filename"] == sample_id), None)
    if not matched:
        # Fallback to direct filename lookup
        safe_name = Path(sample_id).name
        target = EXAMPLES_DIR / safe_name
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"Demo sample '{sample_id}' not found")
        return _run_forensic_pipeline(target)

    target = EXAMPLES_DIR / matched["filename"]
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Demo sample file '{matched['filename']}' not found on server")
    return _run_forensic_pipeline(target)


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Please upload a valid .eml file")

    content_bytes = await file.read()
    if len(content_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File size exceeds 25 MB limit")

    safe_name = re.sub(r"[^\w\-. ]", "_", Path(file.filename).name)
    if not safe_name.lower().endswith(".eml"):
        safe_name += ".eml"

    file_path = UPLOAD_DIR / safe_name
    file_path.write_bytes(content_bytes)

    return _run_forensic_pipeline(file_path)


@app.get("/api/reports/{filename}")
def download_report(filename: str):
    safe_path = (REPORTS_DIR / filename).resolve()
    if not safe_path.is_relative_to(REPORTS_DIR.resolve()) or not safe_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path=safe_path, filename=filename)
