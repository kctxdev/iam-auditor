"""Coleta somente leitura do estado do IAM via boto3. Gera um 'snapshot' serializavel (dict/JSON)."""
from __future__ import annotations

import csv
import io
import time

from botocore.exceptions import ClientError

from .util import parse_dt


def _iso(v):
    dt = parse_dt(v)
    return dt.isoformat() if dt else None


def _pages(client, op, key, **kw):
    for page in client.get_paginator(op).paginate(**kw):
        yield from page[key]


def _credential_report(iam, timeout=60) -> list[dict]:
    deadline = time.time() + timeout
    while iam.generate_credential_report()["State"] != "COMPLETE":
        if time.time() > deadline:
            raise TimeoutError("credential report não ficou pronto a tempo")
        time.sleep(2)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def _policy_document(iam, arn):
    pol = iam.get_policy(PolicyArn=arn)["Policy"]
    ver = iam.get_policy_version(PolicyArn=arn, VersionId=pol["DefaultVersionId"])
    return {"name": pol["PolicyName"], "aws_managed": arn.startswith("arn:aws:iam::aws:"),
            "document": ver["PolicyVersion"]["Document"], "attachment_count": pol.get("AttachmentCount", 0)}


def _principal(iam, kind, name, arn, policies, extra=None):
    """Politicas anexadas e inline de user/group/role. Registra os documentos gerenciados em `policies`."""
    cap = kind.capitalize()
    attached, inline = [], []
    for a in _pages(iam, f"list_attached_{kind}_policies", "AttachedPolicies", **{f"{cap}Name": name}):
        attached.append({"name": a["PolicyName"], "arn": a["PolicyArn"]})
        if a["PolicyArn"] not in policies:
            policies[a["PolicyArn"]] = _policy_document(iam, a["PolicyArn"])
    for pn in _pages(iam, f"list_{kind}_policies", "PolicyNames", **{f"{cap}Name": name}):
        doc = getattr(iam, f"get_{kind}_policy")(**{f"{cap}Name": name, "PolicyName": pn})["PolicyDocument"]
        inline.append({"name": pn, "document": doc})
    return {"name": name, "arn": arn, "attached": attached, "inline": inline, **(extra or {})}


def _access_analyzer(session) -> dict | None:
    """Findings do IAM Access Analyzer (acesso externo/público). None se não houver analyzer."""
    aa = session.client("accessanalyzer")
    try:
        analyzers = [a for a in aa.list_analyzers()["analyzers"] if a["status"] == "ACTIVE"]
    except ClientError:
        return None
    if not analyzers:
        return None
    out = []
    for an in analyzers:
        try:
            for page in aa.get_paginator("list_findings_v2").paginate(
                    analyzerArn=an["arn"], filter={"status": {"eq": ["ACTIVE"]}}):
                for f in page["findings"]:
                    out.append({"id": f["id"], "resource": f.get("resource", ""), "resource_type": f.get("resourceType", ""),
                                "is_public": bool(f.get("isPublic")), "finding_type": f.get("findingType", ""),
                                "principal": f.get("principal", "") if isinstance(f.get("principal"), str) else "externo",
                                "analyzer": an["name"]})
        except ClientError:
            continue
    return {"analyzers": [a["name"] for a in analyzers], "findings": out}


def collect_snapshot(session) -> dict:
    iam = session.client("iam")
    account = session.client("sts").get_caller_identity()["Account"]
    policies: dict = {}
    snap = {"account_id": account, "users": [], "groups": [], "roles": [], "policies": policies,
            "credential_report": [], "access_analyzer": None, "advisor": {}}

    snap["credential_report"] = _credential_report(iam)

    for u in _pages(iam, "list_users", "Users"):
        groups = [g["GroupName"] for g in _pages(iam, "list_groups_for_user", "Groups", UserName=u["UserName"])]
        snap["users"].append(_principal(iam, "user", u["UserName"], u["Arn"], policies,
                                        {"created": _iso(u["CreateDate"]), "groups": groups}))
    for g in _pages(iam, "list_groups", "Groups"):
        snap["groups"].append(_principal(iam, "group", g["GroupName"], g["Arn"], policies))
    for r in _pages(iam, "list_roles", "Roles"):
        if r["Path"].startswith("/aws-service-role/"):  # service-linked roles: gerenciadas pela AWS
            continue
        last = iam.get_role(RoleName=r["RoleName"])["Role"].get("RoleLastUsed", {})
        snap["roles"].append(_principal(iam, "role", r["RoleName"], r["Arn"], policies, {
            "created": _iso(r["CreateDate"]), "trust": r["AssumeRolePolicyDocument"],
            "last_used": _iso(last.get("LastUsedDate")), "last_used_region": last.get("Region")}))

    snap["access_analyzer"] = _access_analyzer(session)
    return snap


def collect_advisor(session, arns: list[str], timeout=90, progress=None) -> dict:
    """IAM Access Advisor: ultimo acesso por servico (e por acao, quando suportado)."""
    iam = session.client("iam")
    result = {}
    for i, arn in enumerate(arns, 1):
        if progress:
            progress(i, len(arns), arn)
        try:
            job = iam.generate_service_last_accessed_details(Arn=arn, Granularity="ACTION_LEVEL")["JobId"]
        except ClientError:
            continue
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = iam.get_service_last_accessed_details(JobId=job)
            if r["JobStatus"] != "IN_PROGRESS":
                break
            time.sleep(1)
        else:
            continue
        if r["JobStatus"] != "COMPLETED":
            continue
        services = list(r["ServicesLastAccessed"])
        while r.get("IsTruncated"):
            r = iam.get_service_last_accessed_details(JobId=job, Marker=r["Marker"])
            services += r["ServicesLastAccessed"]
        result[arn] = [{
            "service_namespace": s["ServiceNamespace"],
            "last_authenticated": _iso(s.get("LastAuthenticated")),
            "actions": [{"name": a["ActionName"], "last_accessed": _iso(a.get("LastAccessedTime"))}
                        for a in s.get("TrackedActionsLastAccessed", [])],
        } for s in services]
    return result
