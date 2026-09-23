#!/usr/bin/env python3
"""
==============================================================================
 main.py — Phishing-EML-Analyzer CLI Orchestrator (Multilingual & Bulk Engine)
==============================================================================
 Phishing-EML-Analyzer | Blue Team Engineering Project
 Author  : alfaggodoy · github.com/alfaggodoy
 License : MIT

 FEATURES:
 - Single file (-f) or Bulk Directory Recursion (-d)
 - Spanish & English CLI interface (--lang es / --lang en)
 - Dual AI Provider: OpenAI Cloud or Local Ollama (--ai-provider local/openai)
 - Rich Terminal Rendering with Batch Summary Matrix
==============================================================================
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import box

load_dotenv()

from src.email_parser       import parse_eml
from src.auth_validator     import validate_authentication
from src.network_forensics  import trace_network_hops
from src.static_extractor   import extract_iocs
from src.ai_analyzer        import analyze_semantics
from src.sandbox_detonator  import detonate
from src.reporter           import generate_report

console = Console()


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-eml-analyzer",
        description=(
            "🛡️  Phishing-EML-Analyzer — Automated Email Forensic & SOAR Engine\n"
            "Analyzes .eml files for phishing, BEC, and social engineering indicators."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--file",
        metavar="EML_PATH",
        help="Path to a single .eml file to analyze.",
    )
    group.add_argument(
        "-d", "--dir",
        metavar="DIR_PATH",
        help="Path to a directory containing .eml files for bulk analysis.",
    )

    parser.add_argument(
        "-o", "--output",
        default="reportes",
        metavar="OUTPUT_DIR",
        help="Directory to save generated reports (default: reportes/).",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "es"],
        default="en",
        help="CLI and report language: 'en' (English, default) or 'es' (Spanish).",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        default=False,
        help="Enable AI-powered semantic analysis.",
    )
    parser.add_argument(
        "--ai-provider",
        choices=["auto", "openai", "ollama", "rule-based"],
        default="auto",
        help="AI provider: 'auto', 'openai' (Cloud), 'ollama' (Local 100%% Private), or 'rule-based'.",
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434/v1",
        help="Ollama API endpoint (default: http://localhost:11434/v1).",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        default=False,
        help="Skip dynamic sandbox detonation (offline-safe mode).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose DEBUG logging.",
    )

    return parser


def _score_color(score: int) -> str:
    if score <= 30:
        return "green"
    elif score <= 60:
        return "yellow"
    elif score <= 80:
        return "dark_orange"
    else:
        return "red"


def _render_banner(lang: str = "en") -> None:
    banner = Text()
    banner.append("🛡️  PHISHING-EML-ANALYZER", style="bold cyan")
    banner.append("  ·  ", style="dim")
    sub = (
        "Motor de Análisis Forense de Email y Respuesta SOAR Automática"
        if lang == "es" else
        "Automated Email Forensic Engine & SOAR Response Pipeline"
    )
    banner.append(sub, style="italic dim white")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))
    console.print()


def _render_verdict_panel(verdict, lang: str = "en") -> None:
    score = verdict.global_score
    color = _score_color(score)
    label = verdict.risk_label

    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)

    content = Text()
    title_label = "PUNTAJE GLOBAL DE RIESGO" if lang == "es" else "GLOBAL RISK SCORE"
    content.append(f"\n  {title_label}  ", style=f"bold {color}")
    content.append(f"{score}/100\n", style=f"bold {color}")
    content.append(f"\n  [{score_bar}]  {label}\n\n", style=color)

    for tag in verdict.soar_tags:
        content.append(f"  {tag.tag}\n", style=f"bold {_score_color(score)}")

    content.append(f"\n  Incident ID:  {verdict.incident_id}\n", style="dim")
    content.append(f"  Timestamp:    {verdict.timestamp_utc}\n", style="dim")

    panel_title = "[bold]🔴 VEREDICTO FINAL[/bold]" if lang == "es" else "[bold]🔴 FINAL VERDICT[/bold]"
    console.print(Panel(content, title=panel_title, border_style=color, padding=(0, 2)))
    console.print()


def _render_findings_table(verdict, lang: str = "en") -> None:
    table_title = "📋 Matriz de Hallazgos" if lang == "es" else "📋 Analysis Findings"
    layer_header = "Capa" if lang == "es" else "Layer"
    findings_header = "Hallazgos Clave" if lang == "es" else "Key Findings"

    table = Table(
        title=table_title,
        box=box.ROUNDED,
        border_style="dim white",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column(layer_header, style="bold", width=12)
    table.add_column("Score", justify="center", width=8)
    table.add_column(findings_header, overflow="fold")

    table.add_row(
        "Network",
        f"[{_score_color(verdict.network_score)}]{verdict.network_score}/100[/]",
        "\n".join([f.replace("**", "") for f in verdict.network_findings[:5]]) if verdict.network_findings else "—",
    )
    table.add_row(
        "Semantic",
        f"[{_score_color(verdict.semantic_score)}]{verdict.semantic_score}/100[/]",
        "\n".join([f.replace("**", "") for f in verdict.semantic_findings]) if verdict.semantic_findings else "—",
    )
    table.add_row(
        "Dynamic",
        f"[{_score_color(verdict.dynamic_score)}]{verdict.dynamic_score}/100[/]",
        "\n".join([f.replace("**", "") for f in verdict.dynamic_findings[:5]]) if verdict.dynamic_findings else "—",
    )

    console.print(table)
    console.print()


def _render_batch_summary(verdicts: list, lang: str = "en") -> None:
    title = "📊 RESUMEN EJECUTIVO DE BATCH (LOTE RECURSIVO)" if lang == "es" else "📊 BATCH EXECUTIVE SUMMARY (RECURSIVE SCAN)"
    table = Table(
        title=title,
        box=box.HEAVY_HEAD,
        border_style="cyan",
        header_style="bold yellow",
        show_lines=True,
    )

    table.add_column("File / Sample", style="bold white", width=32)
    table.add_column("Risk Score", justify="center", width=12)
    table.add_column("Verdict Label", justify="center", width=18)
    table.add_column("Priority & SLA", justify="center", width=16)
    table.add_column("Primary SOAR Tag", style="dim", overflow="fold")

    for v in verdicts:
        score_str = f"[{_score_color(v.global_score)}]{v.global_score}/100[/]"
        label_str = f"[{_score_color(v.global_score)}]{v.risk_label}[/]"
        prio = v.soar_tags[0].priority if v.soar_tags else "P4"
        sla = f"{v.soar_tags[0].sla_minutes}m" if v.soar_tags and v.soar_tags[0].sla_minutes else "None"
        tag_str = v.soar_tags[0].tag if v.soar_tags else "-"
        table.add_row(Path(v.source_file).name, score_str, label_str, f"{prio} ({sla})", tag_str)

    console.print(table)
    console.print()


def _process_single_file(eml_path: Path, args: argparse.Namespace, progress=None) -> object:
    api_key = os.environ.get("OPENAI_API_KEY", "") if args.ai else ""
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "") if not args.no_sandbox else ""
    vt_key = os.environ.get("VT_API_KEY", "") if not args.no_sandbox else ""

    parsed = parse_eml(str(eml_path))
    auth = validate_authentication(parsed)
    net = trace_network_hops(parsed)
    iocs = extract_iocs(parsed)

    ai = analyze_semantics(
        from_address=parsed.from_address,
        subject=parsed.subject,
        body_plain=parsed.body_plain,
        body_html=parsed.body_html,
        provider=args.ai_provider if args.ai else "rule-based",
        api_key=api_key,
        ollama_host=args.ollama_host,
        lang=args.lang,
    )

    if not args.no_sandbox:
        urls_to_detonate = [u.url for u in iocs.urls]
        attachments = [{"sha256": a.sha256, "filename": a.filename} for a in parsed.attachments]
        sandbox = detonate(
            urls=urls_to_detonate,
            attachments=attachments,
            screenshots_dir="screenshots",
            urlscan_api_key=urlscan_key,
            vt_api_key=vt_key,
        )
    else:
        from src.sandbox_detonator import SandboxResult
        skip_msg = "ℹ️ Detonación en Sandbox omitida (flag --no-sandbox)" if args.lang == "es" else "ℹ️ Sandbox detonation skipped (--no-sandbox flag)"
        sandbox = SandboxResult(
            url_scan_results=[], vt_hash_results=[], dynamic_score=0,
            dynamic_findings=[skip_msg],
            screenshots_downloaded=[],
        )

    verdict = generate_report(
        parsed=parsed, auth=auth, net=net, iocs=iocs,
        ai=ai, sandbox=sandbox, output_dir=args.output,
        lang=args.lang,
    )
    return verdict


def main() -> None:
    parser = _build_argument_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stderr),
            logging.FileHandler("logs/audit.log", mode="a", encoding="utf-8"),
        ],
    )
    Path("logs").mkdir(exist_ok=True)

    _render_banner(args.lang)

    # --- Single File Mode ---
    if args.file:
        eml_file = Path(args.file)
        if not eml_file.exists():
            console.print(f"[bold red]❌ File not found:[/bold red] {eml_file}")
            sys.exit(1)

        verdict = _process_single_file(eml_file, args)
        _render_verdict_panel(verdict, args.lang)
        _render_findings_table(verdict, args.lang)

        console.print(f"[cyan]📄 Report generated:[/cyan] {verdict.markdown_report_path}")
        console.print(f"[cyan]📦 JSON STIX export:[/cyan] {verdict.json_report_path}")
        console.print()

    # --- Bulk Directory Mode ---
    elif args.dir:
        dir_path = Path(args.dir)
        if not dir_path.exists() or not dir_path.is_dir():
            console.print(f"[bold red]❌ Directory not found:[/bold red] {dir_path}")
            sys.exit(1)

        eml_files = sorted(list(dir_path.glob("**/*.eml")))
        if not eml_files:
            console.print(f"[bold yellow]⚠️ No .eml files found in directory:[/bold yellow] {dir_path}")
            sys.exit(0)

        console.print(f"[bold cyan]🔍 Found {len(eml_files)} .eml files in {dir_path}. Starting batch analysis...[/bold cyan]\n")

        verdicts = []
        for eml in eml_files:
            console.print(f"  • Processing: [bold white]{eml.name}[/bold white]...", end=" ")
            try:
                v = _process_single_file(eml, args)
                verdicts.append(v)
                console.print(f"[{_score_color(v.global_score)}]Done ({v.global_score}/100 {v.risk_label})[/]")
            except Exception as exc:
                console.print(f"[bold red]FAILED ({exc})[/bold red]")

        console.print()
        _render_batch_summary(verdicts, args.lang)


if __name__ == "__main__":
    main()
