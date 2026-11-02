"""Sugestões de menor privilégio baseadas no IAM Access Advisor (último acesso por serviço/ação)."""
from __future__ import annotations

from datetime import timedelta

from .util import parse_dt, principal_index

_TARGET = {"ALLOW_ALL_ACTIONS", "SERVICE_WILDCARD"}


def enrich(findings, snapshot: dict, now, window_days: int = 365) -> None:
    advisor = snapshot.get("advisor") or {}
    if not advisor:
        return
    idx = principal_index(snapshot)
    cutoff = now - timedelta(days=window_days)
    for f in findings:
        if f.code not in _TARGET:
            continue
        arns = [idx[a] for a in f.affected if idx.get(a) in advisor]
        if not arns:
            continue
        used: set[str] = set()
        observed: dict[str, set[str]] = {}
        for arn in arns:
            for svc in advisor[arn]:
                ns = svc["service_namespace"].lower()
                la = parse_dt(svc.get("last_authenticated"))
                if la and la >= cutoff:
                    used.add(ns)
                    for ac in svc.get("actions", []):
                        at = parse_dt(ac.get("last_accessed"))
                        if at and at >= cutoff:
                            observed.setdefault(ns, set()).add(ac["name"])
        wild = {a.split(":")[0].lower() for a in f.evidence.get("wildcard_actions", [])}
        never = sorted(wild - used) if f.code == "SERVICE_WILDCARD" else []
        if f.code == "SERVICE_WILDCARD":
            used &= wild
        f.evidence["advisor_window_days"] = window_days
        if never:
            f.evidence["services_never_used"] = never
        if not used:
            f.recommendation += (f" Access Advisor: nenhum desses serviços foi acessado nos últimos {window_days} dias - "
                                 "remova o statement/política.")
            continue
        f.evidence["services_used"] = sorted(used)
        if observed:
            f.evidence["actions_observed"] = {k: sorted(v) for k, v in observed.items() if k in used}
        f.recommendation += (f" Access Advisor: serviços usados nos últimos {window_days} dias: {', '.join(sorted(used))}. "
                             "A política sugerida é um primeiro passo (nível de serviço); refine para ações com a geração "
                             "de política do Access Analyzer (CloudTrail).")
        f.suggested_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "LeastPrivilegeFromAccessAdvisor", "Effect": "Allow",
                           "Action": [f"{s}:*" for s in sorted(used)], "Resource": "*"}],
        }
