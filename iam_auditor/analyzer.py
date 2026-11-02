"""Lógica de análise (pura, sem chamadas de rede) sobre um snapshot do IAM."""
from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone

from .models import SEV_RANK, SEV_WEIGHT, SEVERITIES, Finding
from .recommender import enrich
from .util import as_list, parse_dt, principal_index

# Ações que permitem escalar privilegios quando concedidas com Resource "*"
PRIVESC_ACTIONS = [
    "iam:PassRole", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup", "sts:AssumeRole",
    "lambda:UpdateFunctionCode", "ec2:RunInstances",
]
SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations", "secretsmanager", "cloudtrail", "account"}
WILDCARD_CODES = {"ALLOW_ALL_ACTIONS", "SERVICE_WILDCARD", "NOT_ACTION_ALLOW"}
_TRUST_GUARDS = {"sts:externalid", "aws:principalorgid", "aws:principalorgpaths", "aws:sourcearn", "aws:sourceaccount"}


# --------------------------------------------------------------------------- políticas
def _issue(code, severity, title, description, recommendation, evidence):
    return dict(code=code, severity=severity, title=title, description=description,
                recommendation=recommendation, evidence=evidence)


def policy_issues(doc: dict) -> list[dict]:
    issues = []
    for i, st in enumerate(as_list((doc or {}).get("Statement"))):
        if st.get("Effect") != "Allow":
            continue
        sid = st.get("Sid", f"#{i}")
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        has_cond = bool(st.get("Condition"))
        res_star = "*" in resources
        ev = {"statement": sid, "actions": actions, "resources": resources, "has_condition": has_cond}

        if "NotAction" in st:
            ev["not_actions"] = as_list(st.get("NotAction"))
            issues.append(_issue(
                "NOT_ACTION_ALLOW", "HIGH", "Allow com NotAction (libera tudo, exceto o listado)",
                f"O statement {sid} usa Allow + NotAction, concedendo implicitamente todas as ações não listadas, inclusive as futuras.",
                "Reescreva com uma lista explicita de Action (allow-list) em vez de exceções.", ev))
            continue

        if "*" in actions:
            sev = ("HIGH" if has_cond else "CRITICAL") if res_star else "HIGH"
            issues.append(_issue(
                "ALLOW_ALL_ACTIONS", sev, "Permissão total (Action: *)",
                f"O statement {sid} permite Action \"*\" em {'todos os recursos' if res_star else 'recursos específicos'}"
                f"{' (com Condition)' if has_cond else ''}: acesso administrativo.",
                "Substitua por uma lista das ações realmente usadas. Use Access Advisor / geração de política do "
                "Access Analyzer a partir do CloudTrail para chegar ao menor privilégio.", ev))
            continue

        wild = [a for a in actions if a.endswith(":*")]
        if wild:
            sensitive = [a for a in wild if a.split(":")[0].lower() in SENSITIVE_SERVICES]
            if res_star and sensitive:
                sev = "HIGH" if has_cond else "CRITICAL"
            elif res_star:
                sev = "HIGH"
            else:
                sev = "MEDIUM"
            ev["wildcard_actions"] = wild
            issues.append(_issue(
                "SERVICE_WILDCARD", sev, f"Wildcard de serviço ({', '.join(wild)})",
                f"O statement {sid} concede todas as ações de {', '.join(wild)} "
                f"{'em todos os recursos' if res_star else 'nos recursos listados'}.",
                "Liste apenas as ações necessárias (ex.: s3:GetObject, s3:PutObject) e restrinja o Resource a ARNs específicos.", ev))
            ev = {k: v for k, v in ev.items() if k != "wildcard_actions"}  # evidência separada p/ os proximos checks

        # ações ja cobertas por um wildcard de serviço não sao reavaliadas
        check = [a for a in actions if not a.endswith(":*")]
        privesc = [p for p in PRIVESC_ACTIONS
                   if any(fnmatch.fnmatchcase(p.lower(), a.lower()) for a in check)]
        if privesc and res_star and not has_cond:
            ev["privesc_actions"] = privesc
            issues.append(_issue(
                "PRIVESC_ACTIONS", "HIGH", "Ações de escalada de privilégio em Resource: *",
                f"O statement {sid} permite {', '.join(privesc)} em qualquer recurso, caminho comum de escalada de privilégio.",
                "Restrinja o Resource a ARNs específicos e adicione Condition (ex.: iam:PassedToService, permissions boundary).", ev))
        elif any("*" in a for a in check) and res_star:
            issues.append(_issue(
                "PARTIAL_WILDCARD", "LOW", "Wildcard parcial de ações com Resource: *",
                f"O statement {sid} usa padrões ({', '.join(a for a in check if '*' in a)}) em todos os recursos.",
                "Prefira ações explicitas e recursos específicos.", ev))

        if "NotResource" in st:
            issues.append(_issue(
                "NOT_RESOURCE_ALLOW", "MEDIUM", "Allow com NotResource",
                f"O statement {sid} usa NotResource, liberando tudo menos os recursos listados.",
                "Use Resource com ARNs explicitos.", ev))
    return issues


def _account_of(principal: str) -> str | None:
    if re.fullmatch(r"\d{12}", principal):
        return principal
    m = re.match(r"arn:aws[\w-]*:iam::(\d{12}):", principal)
    return m.group(1) if m else None


def trust_issues(trust: dict, own_account: str) -> list[dict]:
    issues = []
    for i, st in enumerate(as_list((trust or {}).get("Statement"))):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        aws = ["*"] if principal == "*" else as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        cond = st.get("Condition") or {}
        guards = {k.lower() for op in cond.values() if isinstance(op, dict) for k in op}
        guarded = bool(guards & _TRUST_GUARDS)
        if "*" in aws:
            sev = "MEDIUM" if cond else "CRITICAL"
            issues.append(_issue(
                "TRUST_WILDCARD", sev, "Trust policy permite qualquer principal (*)",
                "Qualquer conta/identidade AWS pode tentar assumir esta role" + (" (mitigado por Condition - revisar)." if cond else "."),
                "Restrinja o Principal a contas/roles específicas e exija sts:ExternalId ou aws:PrincipalOrgID.",
                {"statement": st.get("Sid", f"#{i}"), "principal": aws, "condition": cond}))
            continue
        for p in aws:
            acct = _account_of(str(p))
            if acct and acct != own_account and not guarded:
                issues.append(_issue(
                    "TRUST_EXTERNAL_NO_GUARD", "MEDIUM", f"Conta externa {acct} sem ExternalId/OrgID",
                    f"A role confia na conta {acct} sem sts:ExternalId nem aws:PrincipalOrgID (risco de confused deputy).",
                    "Adicione Condition com sts:ExternalId (terceiros) ou aws:PrincipalOrgID (sua organização).",
                    {"statement": st.get("Sid", f"#{i}"), "principal": p}))
    return issues


# --------------------------------------------------------------------------- credenciais
def _days(now, dt):
    return (now - dt).days


def credential_findings(snapshot: dict, now: datetime, stale_days: int, key_max_age: int) -> list[Finding]:
    out: list[Finding] = []

    def add(row, code, sev, title, desc, rec, ev=None, cat="credentials"):
        name = "root" if row["user"] == "<root_account>" else row["user"]
        out.append(Finding(code, sev, cat, "root" if name == "root" else "user", name, row.get("arn", ""),
                           title, desc, rec, ev or {}))

    for row in snapshot.get("credential_report", []):
        is_root = row["user"] == "<root_account>"
        pw = row.get("password_enabled") == "true"
        mfa = row.get("mfa_active") == "true"
        if is_root:
            if not mfa:
                add(row, "ROOT_NO_MFA", "CRITICAL", "Conta root sem MFA",
                    "O usuário root não tem MFA ativo.", "Ative MFA (preferencialmente hardware/passkey) no root imediatamente.")
            used = parse_dt(row.get("password_last_used"))
            if used and _days(now, used) < 30:
                add(row, "ROOT_RECENT_USE", "MEDIUM", "Root usado nos últimos 30 dias",
                    f"Último uso do root: {used.date()}.", "Use o root somente para tarefas que exigem; prefira roles/SSO.")
        elif pw and not mfa:
            add(row, "USER_NO_MFA", "HIGH", "Usuário com console sem MFA",
                "O usuário tem senha de console habilitada e nenhum MFA.", "Exija MFA (política com aws:MultiFactorAuthPresent) ou migre para IAM Identity Center.")

        if pw and not is_root:
            last = parse_dt(row.get("password_last_used")) or parse_dt(row.get("user_creation_time"))
            if last and _days(now, last) > stale_days:
                add(row, "CONSOLE_UNUSED", "MEDIUM", f"Senha de console sem uso há {_days(now, last)} dias",
                    "Credencial de console ociosa aumenta a superficie de ataque.", "Desabilite o login profile ou remova o usuário.",
                    {"last_activity": str(last.date())}, cat="unused")

        active_keys = 0
        for n in (1, 2):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            active_keys += 1
            rotated = parse_dt(row.get(f"access_key_{n}_last_rotated"))
            used = parse_dt(row.get(f"access_key_{n}_last_used_date"))
            age = _days(now, rotated) if rotated else None
            ev = {"key_slot": n, "age_days": age, "last_used": str(used.date()) if used else None}
            if is_root:
                add(row, "ROOT_ACCESS_KEY", "CRITICAL", "Root possui access key ativa",
                    "Chaves de acesso do root não podem ser restringidas por IAM.", "Delete a access key do root.", ev)
                continue
            if age is not None and age > key_max_age:
                add(row, "KEY_OLD", "MEDIUM", f"Access key {n} com {age} dias sem rotação",
                    f"A chave não e rotacionada há mais de {key_max_age} dias.", "Rotacione a chave ou troque por roles/credenciais temporárias (OIDC, SSO).", ev)
            if used is None:
                if age is not None and age > 30:
                    add(row, "KEY_NEVER_USED", "LOW", f"Access key {n} nunca usada",
                        "Chave ativa criada há mais de 30 dias e nunca utilizada.", "Delete a chave.", ev, "unused")
            elif _days(now, used) > stale_days:
                add(row, "KEY_UNUSED", "MEDIUM", f"Access key {n} sem uso há {_days(now, used)} dias",
                    "Chave ativa porém ociosa.", "Desative e, após validar, delete a chave.", ev, "unused")
        if active_keys == 2 and not is_root:
            add(row, "TWO_ACTIVE_KEYS", "LOW", "Usuário com duas access keys ativas",
                "Mantenha duas chaves apenas durante a rotação.", "Desative/delete a chave antiga após a migração.")
    return out


# --------------------------------------------------------------------------- orquestracao
def analyze(snapshot: dict, now: datetime | None = None, stale_days: int = 90,
            key_max_age: int = 90, advisor_window_days: int = 365) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    own = snapshot.get("account_id", "")
    findings: list[Finding] = []

    def from_issues(issues, cat, rtype, name, arn, affected):
        for it in issues:
            findings.append(Finding(it["code"], it["severity"], cat, rtype, name, arn, it["title"],
                                    it["description"], it["recommendation"], it["evidence"], list(affected)))

    # políticas gerenciadas anexadas
    amap: dict[str, list[str]] = {}
    for kind in ("users", "groups", "roles"):
        for p in snapshot.get(kind, []):
            for a in p.get("attached", []):
                amap.setdefault(a["arn"], []).append(f"{kind[:-1]}:{p['name']}")
    for arn, pol in snapshot.get("policies", {}).items():
        affected = amap.get(arn, [])
        if affected:
            from_issues(policy_issues(pol["document"]), "policy", "policy", pol["name"], arn, affected)

    # políticas inline + higiene + trust + roles ociosas
    for kind in ("users", "groups", "roles"):
        t = kind[:-1]
        for p in snapshot.get(kind, []):
            who = f"{t}:{p['name']}"
            for inl in p.get("inline", []):
                from_issues(policy_issues(inl["document"]), "policy", "inline-policy", f"{p['name']}/{inl['name']}",
                            f"{p['arn']}#inline/{inl['name']}", [who])
            if t == "user" and (p.get("attached") or p.get("inline")):
                findings.append(Finding(
                    "USER_DIRECT_POLICY", "LOW", "hygiene", "user", p["name"], p["arn"],
                    "Políticas anexadas diretamente ao usuário",
                    "Permissões diretas dificultam auditoria e revisao de acesso.",
                    "Agrupe permissões em grupos/roles (ou IAM Identity Center) e anexe-as la.",
                    {"attached": [a["name"] for a in p.get("attached", [])], "inline": [i["name"] for i in p.get("inline", [])]}))
            if t == "role":
                from_issues(trust_issues(p.get("trust", {}), own), "trust", "role", p["name"], p["arn"], [who])
                last = parse_dt(p.get("last_used"))
                created = parse_dt(p.get("created"))
                if last is None and created and _days(now, created) > stale_days:
                    findings.append(Finding("ROLE_NEVER_USED", "MEDIUM", "unused", "role", p["name"], p["arn"],
                                            "Role nunca utilizada", f"Role criada há {_days(now, created)} dias sem nenhum uso registrado.",
                                            "Remova a role ou documente por que ela deve existir.", {"created": str(created.date())}))
                elif last and _days(now, last) > stale_days:
                    findings.append(Finding("ROLE_UNUSED", "MEDIUM", "unused", "role", p["name"], p["arn"],
                                            f"Role sem uso há {_days(now, last)} dias", "Role ociosa mantem permissões sem necessidade.",
                                            "Remova a role ou reduza suas permissões.", {"last_used": str(last.date())}))

    findings += credential_findings(snapshot, now, stale_days, key_max_age)

    # IAM Access Analyzer
    aa = snapshot.get("access_analyzer") or {}
    for f in aa.get("findings", []):
        pub = f.get("is_public")
        findings.append(Finding(
            "ACCESS_ANALYZER_" + ("PUBLIC" if pub else "EXTERNAL"), "HIGH" if pub else "MEDIUM", "access-analyzer",
            f.get("resource_type", "resource"), f.get("resource", ""), f.get("resource", ""),
            f"Access Analyzer: acesso {'público' if pub else 'externo'} em {f.get('resource_type', 'recurso')}",
            f"O recurso é acessível por {f.get('principal', 'principal externo')}.",
            "Revise a resource policy e remova o acesso externo se não for intencional (ou arquive o finding se for).",
            {k: v for k, v in f.items() if k not in ("resource", "resource_type")}))

    enrich(findings, snapshot, now, advisor_window_days)
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category, f.resource_name))
    return findings


def affected_arns(findings: list[Finding], snapshot: dict) -> list[str]:
    idx = principal_index(snapshot)
    arns = []
    for f in findings:
        if f.code in WILDCARD_CODES:
            arns += [idx[a] for a in f.affected if a in idx]
    return sorted(set(arns))


def build_report(snapshot: dict, findings: list[Finding], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    by_sev = {s: 0 for s in SEVERITIES}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] += 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    score = min(100, sum(SEV_WEIGHT[f.severity] for f in findings))
    return {
        "meta": {
            "account_id": snapshot.get("account_id"), "generated_at": now.isoformat(timespec="seconds"),
            "users": len(snapshot.get("users", [])), "roles": len(snapshot.get("roles", [])),
            "groups": len(snapshot.get("groups", [])), "policies_analyzed": len(snapshot.get("policies", {})),
            "access_analyzer": bool(snapshot.get("access_analyzer")), "access_advisor": bool(snapshot.get("advisor")),
            "demo": bool(snapshot.get("demo")),
        },
        "summary": {"total": len(findings), "by_severity": by_sev, "by_category": by_cat, "risk_score": score},
        "findings": [f.to_dict() for f in findings],
    }
