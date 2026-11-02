from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import affected_arns, analyze, build_report
from .models import SEV_RANK, SEVERITIES
from .report import render_html, render_json, render_markdown
from .terminal import render_terminal, use_color


def _parser():
    p = argparse.ArgumentParser(prog="iam-auditor", description="Audita permissões IAM e sugere menor privilégio.")
    p.add_argument("--profile", help="perfil do AWS CLI")
    p.add_argument("--region", default="us-east-1", help="regiao para o Access Analyzer (default: us-east-1)")
    p.add_argument("--demo", action="store_true", help="usa dados fictícios (não acessa a AWS)")
    p.add_argument("--snapshot-in", help="analisa um snapshot JSON salvo (offline)")
    p.add_argument("--snapshot-out", help="salva o snapshot coletado (contem dados sensíveis da conta!)")
    p.add_argument("--advisor", action="store_true", help="consulta o Access Advisor p/ sugerir menor privilégio (mais lento)")
    p.add_argument("--advisor-max", type=int, default=25, help="max. de principais consultados no Access Advisor")
    p.add_argument("--stale-days", type=int, default=90, help="dias sem uso para considerar ocioso (default: 90)")
    p.add_argument("--key-max-age", type=int, default=90, help="idade maxima de access key em dias (default: 90)")
    p.add_argument("--format", default="terminal", help="terminal,html,json,md ou 'all' (default: terminal)")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra descrição, evidencias e política sugerida")
    p.add_argument("--no-color", action="store_true", help="desliga cores")
    p.add_argument("-o", "--output-dir", default="reports")
    p.add_argument("--fail-on", choices=SEVERITIES, help="retorna exit code 1 se houver finding >= severidade (uso em CI)")
    p.add_argument("--ui", action="store_true", help="abre a interface local no navegador")
    p.add_argument("--port", type=int, default=8765, help="porta da interface (default: 8765)")
    p.add_argument("--no-browser", action="store_true", help="não abre o navegador automaticamente")
    p.add_argument("--version", action="version", version=__version__)
    return p


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.ui:
        from .web import serve
        return serve(args.port, open_browser=not args.no_browser)
    session = None

    if args.demo:
        from .demo_data import demo_snapshot
        snapshot = demo_snapshot()
    elif args.snapshot_in:
        snapshot = json.loads(Path(args.snapshot_in).read_text())
    else:
        try:
            import boto3
            from .collector import collect_snapshot
        except ImportError:
            print("boto3 não instalado: pip install -r requirements.txt", file=sys.stderr)
            return 2
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        print("Coletando dados do IAM (somente leitura)...", file=sys.stderr)
        snapshot = collect_snapshot(session)

    findings = analyze(snapshot, stale_days=args.stale_days, key_max_age=args.key_max_age)

    if args.advisor and session is not None:
        from .collector import collect_advisor
        arns = affected_arns(findings, snapshot)[: args.advisor_max]
        print(f"Consultando Access Advisor para {len(arns)} principais...", file=sys.stderr)
        snapshot["advisor"] = collect_advisor(session, arns)
        findings = analyze(snapshot, stale_days=args.stale_days, key_max_age=args.key_max_age)

    if args.snapshot_out:
        Path(args.snapshot_out).write_text(json.dumps(snapshot, indent=2, default=str))

    report = build_report(snapshot, findings)
    formats = ["terminal", "html", "json", "md"] if args.format == "all" else [f.strip() for f in args.format.split(",")]

    if "terminal" in formats:
        print(render_terminal(report, color=use_color(args.no_color), verbose=args.verbose))

    out = Path(args.output_dir)
    renderers = {"html": render_html, "json": render_json, "md": render_markdown}
    written = []
    for fmt in formats:
        if fmt in renderers:
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"iam-audit.{fmt}"
            path.write_text(renderers[fmt](report), encoding="utf-8")
            written.append(str(path))
    if written:
        print("\nRelatorios salvos: " + ", ".join(written), file=sys.stderr)

    if args.fail_on:
        limit = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] <= limit for f in findings):
            return 1
    return 0
