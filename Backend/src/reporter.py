"""
==============================================================================
 src/reporter.py — SOAR Risk Calculator & Multilingual Report Generator
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 PURPOSE
 -------
 Consolidates the outputs of all three analysis layers into a final composite
 Risk Score (0-100), assigns SOAR tags and SLA priorities, and generates
 forensic investigation reports in Markdown (.md) and JSON (STIX) formats.
 Supports English ('en') and Spanish ('es') outputs.
==============================================================================
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .email_parser      import ParsedEmail
from .auth_validator    import AuthResult
from .network_forensics import NetworkForensicsResult
from .static_extractor  import IoCExtractionResult
from .ai_analyzer       import AiAnalysisResult
from .sandbox_detonator import SandboxResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class SoarTag:
    tag: str
    priority: str       # 'P1', 'P2', 'P3', 'P4'
    sla_minutes: Optional[int]
    color: str          # 'red', 'orange', 'yellow', 'green'


@dataclass
class FinalVerdict:
    incident_id: str
    timestamp_utc: str
    source_file: str
    source_sha256: str

    global_score: int           # 0-100
    risk_label: str             # 'LEGITIMATE', 'SUSPICIOUS', 'HIGH_RISK', 'CONFIRMED_PHISHING'

    network_score: int
    semantic_score: int
    dynamic_score: int

    soar_tags: list[SoarTag]

    network_findings: list[str]
    semantic_findings: list[str]
    dynamic_findings: list[str]
    all_findings: list[str]

    markdown_report_path: Optional[str]
    json_report_path: Optional[str]


# ---------------------------------------------------------------------------
# SOAR Tag Assignment
# ---------------------------------------------------------------------------

def _assign_soar_tags(
    global_score: int,
    auth: AuthResult,
    ai: AiAnalysisResult,
    iocs: IoCExtractionResult,
    sandbox: SandboxResult,
) -> list[SoarTag]:
    tags: list[SoarTag] = []

    # 1. Executive Impersonation or Internal BEC (Account Takeover)
    if ai.executive_impersonation and (auth.dmarc_passive == "fail" or ai.financial_request):
        tags.append(SoarTag(
            tag="[P1-CRITICAL] [BEC-Executive-Impersonation]",
            priority="P1", sla_minutes=15, color="red",
        ))

    # 2. Financial Fraud Request & IBAN (Internal BEC / Compromised Account)
    if ai.financial_request and ai.semantic_score >= 70:
        tags.append(SoarTag(
            tag="[P1-CRITICAL] [Account-Takeover-Financial-BEC]",
            priority="P1", sla_minutes=15, color="red",
        ))

    # 3. Confirmed Malicious Phishing URL via Sandbox
    if any(r.verdict_malicious for r in sandbox.url_scan_results):
        tags.append(SoarTag(
            tag="[P1-CRITICAL] [Confirmed-Phishing-URL]",
            priority="P1", sla_minutes=15, color="red",
        ))

    # 4. Credential Harvesting
    if ai.credential_harvesting and (iocs.suspicious_url_count > 0 or auth.dmarc_passive in ("fail", "quarantine")):
        tags.append(SoarTag(
            tag="[P2-HIGH] [Credential-Harvesting]",
            priority="P2", sla_minutes=60, color="orange",
        ))

    # 5. Financial Fraud Request
    if ai.financial_request and (auth.spf_passive in ("fail", "softfail") or auth.dmarc_passive == "fail"):
        tags.append(SoarTag(
            tag="[P2-HIGH] [Financial-Fraud-BEC]",
            priority="P2", sla_minutes=60, color="orange",
        ))

    # 6. Malicious Attachment via VirusTotal
    if any(r.verdict == "malicious" for r in sandbox.vt_hash_results):
        tags.append(SoarTag(
            tag="[P2-HIGH] [Malicious-Attachment]",
            priority="P2", sla_minutes=60, color="orange",
        ))

    # 7. Suspicious Auth or General Suspicious
    if not tags and global_score >= 31:
        tags.append(SoarTag(
            tag="[P3-MEDIUM] [Suspicious-Auth-Failure]",
            priority="P3", sla_minutes=240, color="yellow",
        ))

    # 8. Legitimate Baseline
    if not tags or global_score <= 30:
        tags.append(SoarTag(
            tag="[P4-LOW] [Probable-Legitimate]",
            priority="P4", sla_minutes=None, color="green",
        ))

    return tags


def _calculate_global_score(net: int, sem: int, dyn: int) -> tuple[int, str]:
    weighted = int(round(0.25 * net + 0.35 * sem + 0.40 * dyn))
    
    # Internal BEC / Account Takeover Heuristic:
    # When an internal compromised account passes SPF/DKIM (net=0) but contains high semantic fraud (sem >= 70),
    # the weighted average alone under-scores the risk. Apply a SOC floor boost.
    if sem >= 70 and weighted < sem:
        score = int(round(0.40 * weighted + 0.60 * sem))
    else:
        score = weighted

    score = min(max(score, 0), 100)

    if score <= 30:
        label = "LEGITIMATE"
    elif score <= 60:
        label = "SUSPICIOUS"
    elif score <= 80:
        label = "HIGH_RISK"
    else:
        label = "CONFIRMED_PHISHING"

    return score, label


# ---------------------------------------------------------------------------
# Multilingual Report Generation
# ---------------------------------------------------------------------------

def _render_markdown_report(
    verdict: FinalVerdict,
    parsed: ParsedEmail,
    auth: AuthResult,
    net: NetworkForensicsResult,
    iocs: IoCExtractionResult,
    ai: AiAnalysisResult,
    sandbox: SandboxResult,
    lang: str = "en",
) -> str:
    title = "🛡️ Informe de Investigación Forense" if lang == "es" else "🛡️ Forensic Investigation Report"
    exec_summary = "Resumen Ejecutivo" if lang == "es" else "Executive Summary"
    phase_matrix = "Matriz de Evaluación por Fases" if lang == "es" else "Phase Evaluation Matrix"
    email_title = "Metadatos del Correo" if lang == "es" else "Email Metadata"
    auth_title = "Fase 1: Validación de Autenticación (SPF / DKIM / DMARC)" if lang == "es" else "Phase 1: Authentication Validation"
    ioc_title = "Fase 2: Extracción Estática de IoCs y Enlaces" if lang == "es" else "Phase 2: Static IoC & Link Extraction"
    ai_title = "Fase 3: Análisis de Intención Semántica con IA" if lang == "es" else "Phase 3: AI Semantic Intent Analysis"
    sandbox_title = "Fase 4: Detonación Dinámica en Sandbox & OSINT" if lang == "es" else "Phase 4: Dynamic Sandbox Detonation & OSINT"
    soar_title = "Respuesta SOAR y Clasificación de Incidente" if lang == "es" else "SOAR Response & Incident Classification"

    tags_str = " ".join(f"`{t.tag}`" for t in verdict.soar_tags)

    lines = [
        f"# {title} — {verdict.incident_id}",
        "",
        f"> **{tags_str}**",
        "",
        "---",
        "",
        f"## 📊 {exec_summary}",
        "",
        "| Campo | Valor |",
        "|:------|:------|",
        f"| **ID de Incidente**   | `{verdict.incident_id}` |",
        f"| **Marca de Tiempo**   | `{verdict.timestamp_utc}` |",
        f"| **Archivo Origen**    | `{Path(verdict.source_file).name}` |",
        f"| **SHA-256 (Original)**| `{verdict.source_sha256}` |",
        f"| **Risk Score Global** | **{verdict.global_score}/100** — {verdict.risk_label} |",
        f"| **Puntaje Red**       | {verdict.network_score}/100 (peso: 25%) |",
        f"| **Puntaje Semántico** | {verdict.semantic_score}/100 (peso: 35%) |",
        f"| **Puntaje Dinámico**  | {verdict.dynamic_score}/100 (peso: 40%) |",
        f"| **Prioridad**         | {verdict.soar_tags[0].priority if verdict.soar_tags else 'P4'} |",
        f"| **SLA Respuesta**     | {verdict.soar_tags[0].sla_minutes if verdict.soar_tags and verdict.soar_tags[0].sla_minutes else 'Ninguno'} min |",
        "",
        "---",
        "",
        f"## 🔬 {phase_matrix}",
        "",
        "| Fase | Module | Hallazgo Clave | Sub-Score |",
        "|:------|:-------|:------------|:---------:|",
        f"| **Fase 1** — Auth | `auth_validator.py` | SPF: {auth.spf_passive.upper()} · DKIM: {auth.dkim_passive.upper()} · DMARC: {auth.dmarc_passive.upper()} | {verdict.network_score}/100 |",
        f"| **Fase 2** — IA | `ai_analyzer.py` | Urgencia: {ai.urgency_level.upper()} · Motor: {ai.model_used} | {verdict.semantic_score}/100 |",
        f"| **Fase 3** — Sandbox | `sandbox_detonator.py` | Escaneos URL: {len(sandbox.url_scan_results)} · Hashes: {len(sandbox.vt_hash_results)} | {verdict.dynamic_score}/100 |",
        "",
        "---",
        "",
        f"## 📧 {email_title}",
        "",
        "| Field | Value |",
        "|:------|:------|",
        f"| **From**         | `{parsed.from_display_name} <{parsed.from_address}>` |",
        f"| **To**           | `{', '.join(parsed.to_addresses)}` |",
        f"| **Subject**      | `{parsed.subject}` |",
        f"| **Date (Raw)**   | `{parsed.date_raw}` |",
        f"| **Message-ID**   | `{parsed.message_id}` |",
        f"| **Reply-To**     | `{parsed.reply_to or 'Not set'}` |",
        f"| **Return-Path**  | `{parsed.return_path or 'Not set'}` |",
        "",
        "---",
        "",
        f"## 🔐 {auth_title}",
        "",
    ]
    for finding in auth.network_findings:
        lines.append(f"- {finding}")
    lines += [""]

    lines += [
        "### Traza de Saltos de Red (Received Headers)",
        "",
        f"**IP Origen Real:** `{net.origin_ip or 'No identificada'}`  ",
        f"**Total de saltos:** {net.total_hops}",
        "",
    ]
    for hop in net.hops:
        public_ip = f"`{hop.first_public_ip}`" if hop.first_public_ip else "*(privada/interna)*"
        lines.append(f"- **Salto {hop.hop_index + 1}** — IP Pública: {public_ip}")
    lines += ["", "---", ""]

    lines += [f"## 🔗 {ioc_title}", ""]
    for finding in iocs.ioc_findings:
        lines.append(f"- {finding}")
    lines += [""]

    if iocs.urls:
        lines += [
            "### URLs Extraídas",
            "",
            "| URL | Domain | TLD | Suspicious TLD | Brand Impersonation | Anchor Mismatch | Source |",
            "|:----|:-------|:----|:--------------:|:-------------------:|:---------------:|:------:|",
        ]
        for url in iocs.urls[:20]:
            lines.append(
                f"| `{url.url[:60]}` | `{url.domain}` | `.{url.tld}` | "
                f"{'🚨' if url.is_suspicious_tld else '✅'} | "
                f"{'🚨' if url.is_brand_impersonation else '✅'} | "
                f"{'🚨' if url.is_anchor_mismatch else '✅'} | "
                f"{url.source} |"
            )
        lines += [""]

    if parsed.attachments:
        lines += [
            "### Adjuntos (Hashes SHA-256)",
            "",
            "| Filename | MIME Type | Size | SHA-256 |",
            "|:---------|:----------|:-----|:--------|",
        ]
        for att in parsed.attachments:
            lines.append(
                f"| `{att.filename}` | `{att.content_type}` | {att.size_bytes} bytes | `{att.sha256}` |"
            )
        lines += [""]

    lines += ["---", ""]
    lines += [f"## 🤖 {ai_title}", ""]
    for finding in ai.semantic_findings:
        lines.append(f"- {finding}")
    lines += [""]

    if ai.ai_narrative:
        lines += [
            "### Explicación Narrativa de la IA",
            "",
            f"> {ai.ai_narrative}",
            "",
        ]
    lines += ["---", ""]

    lines += [f"## 🧪 {sandbox_title}", ""]
    for finding in sandbox.dynamic_findings:
        lines.append(f"- {finding}")
    lines += [""]

    if sandbox.screenshots_downloaded:
        lines += [
            "### Evidencia Visual — Capturas de Pantalla",
            "",
        ]
        for ss_path in sandbox.screenshots_downloaded:
            lines.append(f"![Sandbox Screenshot]({ss_path})")
        lines += [""]

    lines += ["---", ""]
    lines += [
        f"## 🛡️ {soar_title}",
        "",
        "### Etiquetas Asignadas",
        "",
    ]
    for tag in verdict.soar_tags:
        lines.append(f"- `{tag.tag}` — Prioridad: **{tag.priority}** | SLA: {str(tag.sla_minutes) + ' min' if tag.sla_minutes else 'Ninguno'}")

    lines += [
        "",
        "### Acciones de Contención Recomendadas",
        "",
        "- [ ] Bloquear dominio emisor en pasarela de correo y política SPF",
        "- [ ] Registrar URLs extraídas en plataforma de Threat Intelligence (MISP / OpenCTI)",
        "- [ ] Purgar copias del correo de los buzones corporativos",
        "- [ ] Añadir IP origen a lista de bloqueo del firewall perimetral",
        "- [ ] Notificar al usuario afectado y activar recordatorio de concienciación",
        "",
        "---",
        "",
        f"*Informe generado por phishing-eml-analyzer · {verdict.timestamp_utc} · alfaggodoy*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    parsed:  ParsedEmail,
    auth:    AuthResult,
    net:     NetworkForensicsResult,
    iocs:    IoCExtractionResult,
    ai:      AiAnalysisResult,
    sandbox: SandboxResult,
    output_dir: str = "reportes",
    lang: str = "en",
) -> FinalVerdict:
    global_score, risk_label = _calculate_global_score(
        auth.network_score, ai.semantic_score, sandbox.dynamic_score
    )

    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    soar_tags = _assign_soar_tags(global_score, auth, ai, iocs, sandbox)

    net_findings = auth.network_findings + iocs.ioc_findings
    sem_findings = ai.semantic_findings
    dyn_findings = sandbox.dynamic_findings

    all_findings = net_findings + sem_findings + dyn_findings

    verdict = FinalVerdict(
        incident_id=incident_id,
        timestamp_utc=timestamp_utc,
        source_file=parsed.source_path,
        source_sha256=parsed.source_sha256,
        global_score=global_score,
        risk_label=risk_label,
        network_score=auth.network_score,
        semantic_score=ai.semantic_score,
        dynamic_score=sandbox.dynamic_score,
        soar_tags=soar_tags,
        network_findings=net_findings,
        semantic_findings=sem_findings,
        dynamic_findings=dyn_findings,
        all_findings=all_findings,
        markdown_report_path=None,
        json_report_path=None,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    slug = Path(parsed.source_path).stem.replace(" ", "_")

    md_content = _render_markdown_report(verdict, parsed, auth, net, iocs, ai, sandbox, lang)
    md_path = output_path / f"investigation_report_{slug}.md"
    md_path.write_text(md_content, encoding="utf-8")
    verdict.markdown_report_path = str(md_path)

    json_path = output_path / f"investigation_result_{slug}.json"
    json_data = {
        "incident_id": incident_id,
        "timestamp_utc": timestamp_utc,
        "source_file": parsed.source_path,
        "source_sha256": parsed.source_sha256,
        "global_score": global_score,
        "risk_label": risk_label,
        "network_score": auth.network_score,
        "semantic_score": ai.semantic_score,
        "dynamic_score": sandbox.dynamic_score,
        "soar_tags": [t.tag for t in soar_tags],
        "from_address": parsed.from_address,
        "subject": parsed.subject,
        "origin_ip": net.origin_ip,
        "auth": {
            "spf": auth.spf_passive, "dkim": auth.dkim_passive,
            "dmarc": auth.dmarc_passive, "dmarc_policy": auth.dmarc_policy,
            "reply_to_mismatch": auth.from_reply_to_mismatch,
        },
        "iocs": {
            "url_count": len(iocs.urls),
            "unique_domains": iocs.unique_domains,
            "attachment_hashes": [
                {"filename": a.filename, "sha256": a.sha256}
                for a in parsed.attachments
            ],
        },
        "ai": {
            "urgency_level": ai.urgency_level,
            "detected_tactics": ai.detected_tactics,
            "narrative": ai.ai_narrative,
            "model_used": ai.model_used,
            "provider": ai.provider,
        },
    }
    json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")
    verdict.json_report_path = str(json_path)

    return verdict
