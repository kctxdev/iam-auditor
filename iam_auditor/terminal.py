"""Saida colorida no terminal (sem dependencias externas)."""
from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
SEV_STYLE = {  # (cor do texto, icone)
    "CRITICAL": ("\033[1;97;41m", "✖"), "HIGH": ("\033[1;91m", "▲"), "MEDIUM": ("\033[1;93m", "●"),
    "LOW": ("\033[96m", "○"), "INFO": ("\033[90m", "·"),
}
CY, PU, GR, RD = "\033[96m", "\033[95m", "\033[92m", "\033[91m"


def use_color(force_off: bool = False) -> bool:
    return not force_off and sys.stdout.isatty() and "NO_COLOR" not in os.environ


def render_terminal(report: dict, color: bool = True, verbose: bool = False) -> str:
    def c(code, text):
        return f"{code}{text}{RESET}" if color else text

    width = max(60, min(shutil.get_terminal_size((100, 20)).columns, 110))
    m, s = report["meta"], report["summary"]
    out: list[str] = []
    bar = "─" * width

    title = "IAM Permission Auditor"
    out += ["", c(CY, "┌" + bar),
            c(CY, "│ ") + c(BOLD + CY, title) + c(PU, " ▸ auditoria de permissões AWS"),
            c(CY, "│ ") + c(DIM, f"conta {m['account_id']} | {m['users']} usuários, {m['groups']} grupos, {m['roles']} roles, "
                                 f"{m['policies_analyzed']} políticas"),
            c(CY, "│ ") + c(DIM, f"Access Analyzer: {'sim' if m['access_analyzer'] else 'não'} | "
                                 f"Access Advisor: {'sim' if m['access_advisor'] else 'não'}"
                                 + ("  |  DADOS DE DEMONSTRAÇÃO" if m["demo"] else "")),
            c(CY, "└" + bar), ""]

    if not report["findings"]:
        out.append(c(GR, "✔ Nenhum finding. Nada de excessivo encontrado."))
        return "\n".join(out)

    for n, f in enumerate(report["findings"], 1):
        style, icon = SEV_STYLE[f["severity"]]
        num = c(DIM, "%3d." % n)
        tag = c(style, " %s %s " % (icon, f["severity"]))
        out.append("%s %s %s" % (num, tag, c(BOLD, f["title"])))
        line = "     %s %s %s" % (c(DIM, "recurso:"), f["resource_type"], c(CY, f["resource_name"]))
        if f["affected"]:
            line += "  %s %s" % (c(DIM, "afeta:"), ", ".join(f["affected"]))
        out.append(line)
        rec = f["recommendation"] if verbose else f["recommendation"].split(". ")[0].rstrip(".") + "."
        for i, wrapped in enumerate(textwrap.wrap(rec, width - 12)):
            out.append("     " + c(GR, "→ " if i == 0 else "  ") + wrapped)
        if verbose:
            out.append("     %s %s" % (c(DIM, "problema:"), f["description"]))
            if f.get("suggested_policy"):
                out.append("     " + c(PU, "política sugerida:"))
                out += ["       " + ln for ln in json.dumps(f["suggested_policy"], indent=2).splitlines()]
            if f["evidence"]:
                out.append("     " + c(DIM, "evidência: " + json.dumps(f["evidence"], default=str)))
        out.append("")

    out.append(c(CY, bar))
    out.append(c(BOLD, " Resumo"))
    for sev, qty in s["by_severity"].items():
        if qty:
            style, icon = SEV_STYLE[sev]
            out.append("   %s %3d  %s" % (c(style, " %s %-8s " % (icon, sev)), qty, "█" * min(qty, 40)))
    score = s["risk_score"]
    col = GR if score < 30 else ("\033[93m" if score < 60 else RD)
    filled = score // 5
    out.append("   Risk score: %s  %s%s" % (c(BOLD + col, "%d/100" % score), c(col, "█" * filled), c(DIM, "░" * (20 - filled))))
    out.append(c(CY, bar))
    if not verbose:
        out.append(c(DIM, " dica: use -v para ver detalhes, evidencias e políticas sugeridas"))
    return "\n".join(out)
