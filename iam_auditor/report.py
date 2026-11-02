"""Renderizacao do relatório: JSON, Markdown e HTML autocontido."""
from __future__ import annotations

import json
from html import escape as esc

SEV_COLOR = {"CRITICAL": "#ff3b6b", "HIGH": "#ff8a3d", "MEDIUM": "#f5d142", "LOW": "#4cc9f0", "INFO": "#8892a6"}


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def render_markdown(report: dict) -> str:
    m, s = report["meta"], report["summary"]
    L = [f"# Relatório de auditoria IAM - conta {m['account_id']}", "",
         f"Gerado em {m['generated_at']}{' (DADOS DE DEMONSTRAÇÃO)' if m['demo'] else ''}", "",
         f"**Risk score:** {s['risk_score']}/100 | **Findings:** {s['total']}", "",
         "| Severidade | Qtde |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in s["by_severity"].items()]
    L.append("")
    for f in report["findings"]:
        L += [f"## [{f['severity']}] {f['title']}",
              f"- **Recurso:** {f['resource_type']} `{f['resource_name']}`",
              f"- **Categoria:** {f['category']} (`{f['code']}`)"]
        if f["affected"]:
            L.append(f"- **Afeta:** {', '.join(f['affected'])}")
        L += [f"- **Problema:** {f['description']}", f"- **Correção sugerida:** {f['recommendation']}"]
        if f.get("suggested_policy"):
            L += ["", "```json", json.dumps(f["suggested_policy"], indent=2), "```"]
        L.append("")
    return "\n".join(L)


_CSS = """
:root{--bg:#0b0e17;--panel:#121827;--line:#1f2a44;--txt:#d7e0f2;--mut:#8892a6;--cy:#00e5ff;--pu:#a855f7}
@media (prefers-color-scheme: light){:root{--bg:#f4f6fb;--panel:#fff;--line:#d9e0ee;--txt:#1b2236;--mut:#5b667d;--cy:#007c91;--pu:#7e22ce}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:28px 24px;border-bottom:1px solid var(--line);background:linear-gradient(120deg,rgba(0,229,255,.08),rgba(168,85,247,.08))}
h1{margin:0 0 4px;font-size:22px;color:var(--cy)}h1 span{color:var(--pu)}.mut{color:var(--mut)}
main{max-width:1000px;margin:0 auto;padding:20px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
.card{flex:1;min-width:110px;background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);padding:10px 14px;border-radius:8px}
.card b{display:block;font-size:26px;color:var(--c)}.card span{font-size:12px;color:var(--mut)}
.filters{margin:12px 0}.filters button{background:var(--panel);color:var(--txt);border:1px solid var(--line);padding:5px 12px;border-radius:999px;cursor:pointer;margin:0 6px 6px 0;font:inherit;font-size:12px}
.filters button.on{border-color:var(--cy);color:var(--cy)}
details{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;margin:8px 0}
summary{padding:10px 14px;cursor:pointer}summary em{color:var(--mut);font-style:normal;font-size:12px;margin-left:6px}
.badge{display:inline-block;background:var(--c);color:#111;font-weight:700;font-size:11px;padding:1px 8px;border-radius:4px;margin-right:6px}
.body{padding:2px 16px 14px}.body h4{margin:14px 0 4px;color:var(--pu);font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}
.rec{border-left:3px solid var(--cy);padding-left:10px}
"""

_JS = """
const btns=document.querySelectorAll('.filters button');
btns.forEach(b=>b.onclick=()=>{btns.forEach(x=>x.classList.remove('on'));b.classList.add('on');
const s=b.dataset.s;document.querySelectorAll('details.f').forEach(d=>d.style.display=(s==='ALL'||d.dataset.s===s)?'':'none');});
"""


def render_html(report: dict) -> str:
    m, s = report["meta"], report["summary"]
    cards = "".join(f'<div class="card" style="--c:{SEV_COLOR[k]}"><b>{v}</b><span>{k}</span></div>'
                    for k, v in s["by_severity"].items())
    filters = '<button class="on" data-s="ALL">TODOS</button>' + "".join(
        f'<button data-s="{k}">{k} ({v})</button>' for k, v in s["by_severity"].items() if v)
    items = []
    for f in report["findings"]:
        aff = f'<p><b>Afeta:</b> {esc(", ".join(f["affected"]))}</p>' if f["affected"] else ""
        sp = (f'<h4>Política sugerida (ponto de partida)</h4><pre>{esc(json.dumps(f["suggested_policy"], indent=2))}</pre>'
              if f.get("suggested_policy") else "")
        ev = f'<h4>Evidência</h4><pre>{esc(json.dumps(f["evidence"], indent=2, default=str))}</pre>' if f["evidence"] else ""
        items.append(
            f'<details class="f" data-s="{f["severity"]}" style="--c:{SEV_COLOR[f["severity"]]}"><summary>'
            f'<span class="badge">{f["severity"]}</span><b>{esc(f["title"])}</b>'
            f'<em>{esc(f["resource_type"])}: {esc(f["resource_name"])}</em></summary><div class="body">'
            f'<p>{esc(f["description"])}</p><p class="rec"><b>Correção:</b> {esc(f["recommendation"])}</p>'
            f'{aff}{sp}{ev}<p class="mut">código: {esc(f["code"])} | categoria: {esc(f["category"])}</p></div></details>')
    demo = '<p style="color:var(--pu)">Dados de demonstração (conta ficticia).</p>' if m["demo"] else ""
    return (f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>IAM Audit - {esc(str(m["account_id"]))}</title>'
            f'<style>{_CSS}</style></head><body><header><h1>IAM <span>Permission Auditor</span></h1>'
            f'<div class="mut">Conta {esc(str(m["account_id"]))} | {esc(m["generated_at"])} | {m["users"]} usuários, '
            f'{m["groups"]} grupos, {m["roles"]} roles, {m["policies_analyzed"]} políticas | '
            f'Access Analyzer: {"sim" if m["access_analyzer"] else "não"} | Access Advisor: {"sim" if m["access_advisor"] else "não"}</div>'
            f'</header><main>{demo}<p>Risk score: <b style="color:var(--cy)">{s["risk_score"]}/100</b> '
            f'&middot; {s["total"]} findings</p><div class="cards">{cards}</div><div class="filters">{filters}</div>'
            f'{"".join(items) or "<p>Nenhum finding.</p>"}</main><script>{_JS}</script></body></html>')
