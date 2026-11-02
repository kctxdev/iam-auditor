from datetime import datetime, timezone

from iam_auditor.analyzer import analyze, build_report, policy_issues, trust_issues
from iam_auditor.demo_data import demo_snapshot

NOW = datetime(2026, 10, 31, tzinfo=timezone.utc)


def codes(issues):
    return {i["code"] for i in issues}


def pol(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def test_allow_all_is_critical():
    (i,) = policy_issues(pol({"Effect": "Allow", "Action": "*", "Resource": "*"}))
    assert (i["code"], i["severity"]) == ("ALLOW_ALL_ACTIONS", "CRITICAL")


def test_allow_all_with_condition_is_high():
    (i,) = policy_issues(pol({"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}))
    assert i["severity"] == "HIGH"


def test_deny_is_ignored():
    assert policy_issues(pol({"Effect": "Deny", "Action": "*", "Resource": "*"})) == []


def test_service_wildcard_severity():
    (a,) = policy_issues(pol({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}))
    (b,) = policy_issues(pol({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))
    (c,) = policy_issues(pol({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::x/*"}))
    assert (a["severity"], b["severity"], c["severity"]) == ("CRITICAL", "HIGH", "MEDIUM")


def test_least_privilege_policy_is_clean():
    assert policy_issues(pol({"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"})) == []


def test_privesc_next_to_wildcard():
    issues = policy_issues(pol({"Effect": "Allow", "Action": ["iam:PassRole", "ecr:*"], "Resource": "*"}))
    assert codes(issues) == {"SERVICE_WILDCARD", "PRIVESC_ACTIONS"}


def test_privesc_via_partial_wildcard():
    assert "PRIVESC_ACTIONS" in codes(policy_issues(pol({"Effect": "Allow", "Action": "iam:Put*", "Resource": "*"})))


def test_not_action():
    assert "NOT_ACTION_ALLOW" in codes(policy_issues(pol({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})))


def test_trust_wildcard_and_external():
    t = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    assert trust_issues(t, "123456789012")[0]["severity"] == "CRITICAL"
    ext = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}}]}
    assert codes(trust_issues(ext, "123456789012")) == {"TRUST_EXTERNAL_NO_GUARD"}
    ok = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                         "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}}]}
    assert trust_issues(ok, "123456789012") == []
    same = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}}]}
    assert trust_issues(same, "123456789012") == []


def test_demo_snapshot_findings():
    snap = demo_snapshot(NOW)
    f = analyze(snap, now=NOW)
    got = {x.code for x in f}
    for expected in {"ROOT_NO_MFA", "ROOT_ACCESS_KEY", "USER_NO_MFA", "KEY_OLD", "KEY_UNUSED", "KEY_NEVER_USED",
                     "CONSOLE_UNUSED", "ALLOW_ALL_ACTIONS", "SERVICE_WILDCARD", "PRIVESC_ACTIONS", "TRUST_WILDCARD",
                     "TRUST_EXTERNAL_NO_GUARD", "ROLE_UNUSED", "ROLE_NEVER_USED", "ACCESS_ANALYZER_PUBLIC",
                     "USER_DIRECT_POLICY", "TWO_ACTIVE_KEYS"}:
        assert expected in got, expected
    assert [x.severity for x in f][0] == "CRITICAL"


def test_clean_principals_have_no_findings():
    names = {x.resource_name for x in analyze(demo_snapshot(NOW), now=NOW)}
    assert "AppRole" not in names and "AppReadOnly" not in names


def test_advisor_suggests_used_services_only():
    f = analyze(demo_snapshot(NOW), now=NOW)
    admin = next(x for x in f if x.code == "ALLOW_ALL_ACTIONS")
    assert admin.suggested_policy["Statement"][0]["Action"] == ["iam:*", "s3:*"]  # ec2 nao usado ha 500 dias
    bob = next(x for x in f if x.resource_name == "bob/s3-all")
    assert bob.suggested_policy["Statement"][0]["Action"] == ["s3:*"]


def test_report_summary():
    snap = demo_snapshot(NOW)
    r = build_report(snap, analyze(snap, now=NOW), NOW)
    assert r["summary"]["total"] == len(r["findings"]) and 0 < r["summary"]["risk_score"] <= 100


def test_terminal_render_no_color():
    from iam_auditor.terminal import render_terminal
    snap = demo_snapshot(NOW)
    txt = render_terminal(build_report(snap, analyze(snap, now=NOW), NOW), color=False, verbose=True)
    assert "CRITICAL" in txt and "Risk score" in txt and "\033[" not in txt
