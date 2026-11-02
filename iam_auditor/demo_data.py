"""Snapshot ficticio (conta 123456789012) para testar o auditor sem credenciais AWS."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

ACC = "123456789012"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
DEV_ARN = f"arn:aws:iam::{ACC}:policy/DevFullAccess"
READ_ARN = f"arn:aws:iam::{ACC}:policy/AppReadOnly"


def demo_snapshot(now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)

    def ago(d):
        return (now - timedelta(days=d)).isoformat()

    def cred(user, arn, pw, mfa, pw_used, k1=None, k2=None, created=700):
        row = {"user": user, "arn": arn, "user_creation_time": ago(created), "password_enabled": str(pw).lower(),
               "password_last_used": ago(pw_used) if pw_used is not None else "N/A", "mfa_active": str(mfa).lower()}
        for n, k in ((1, k1), (2, k2)):
            row[f"access_key_{n}_active"] = "true" if k else "false"
            row[f"access_key_{n}_last_rotated"] = ago(k[0]) if k else "N/A"
            row[f"access_key_{n}_last_used_date"] = ago(k[1]) if k and k[1] is not None else "N/A"
        return row

    return {
        "demo": True,
        "account_id": ACC,
        "users": [
            {"name": "alice", "arn": f"arn:aws:iam::{ACC}:user/alice", "groups": ["Admins"], "attached": [], "inline": []},
            {"name": "bob", "arn": f"arn:aws:iam::{ACC}:user/bob", "groups": [], "attached": [{"name": "DevFullAccess", "arn": DEV_ARN}],
             "inline": [{"name": "s3-all", "document": {"Version": "2012-10-17", "Statement": [
                 {"Sid": "S3Everything", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]},
            {"name": "ci-deploy", "arn": f"arn:aws:iam::{ACC}:user/ci-deploy", "groups": [], "attached": [],
             "inline": [{"name": "deploy", "document": {"Version": "2012-10-17", "Statement": [
                 {"Sid": "Deploy", "Effect": "Allow", "Action": ["iam:PassRole", "ecs:UpdateService", "ecr:*"], "Resource": "*"}]}}]},
            {"name": "carol", "arn": f"arn:aws:iam::{ACC}:user/carol", "groups": ["ReadOnly"], "attached": [], "inline": []},
        ],
        "groups": [
            {"name": "Admins", "arn": f"arn:aws:iam::{ACC}:group/Admins", "attached": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}], "inline": []},
            {"name": "ReadOnly", "arn": f"arn:aws:iam::{ACC}:group/ReadOnly", "attached": [{"name": "AppReadOnly", "arn": READ_ARN}], "inline": []},
        ],
        "roles": [
            {"name": "LegacyAdminRole", "arn": f"arn:aws:iam::{ACC}:role/LegacyAdminRole", "created": ago(900), "last_used": ago(400),
             "attached": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}], "inline": [],
             "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}},
            {"name": "VendorAccess", "arn": f"arn:aws:iam::{ACC}:role/VendorAccess", "created": ago(300), "last_used": None,
             "attached": [{"name": "AppReadOnly", "arn": READ_ARN}], "inline": [],
             "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]}},
            {"name": "AppRole", "arn": f"arn:aws:iam::{ACC}:role/AppRole", "created": ago(120), "last_used": ago(2),
             "attached": [{"name": "AppReadOnly", "arn": READ_ARN}], "inline": [],
             "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}},
        ],
        "policies": {
            ADMIN_ARN: {"name": "AdministratorAccess", "aws_managed": True, "attachment_count": 2,
                        "document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
            DEV_ARN: {"name": "DevFullAccess", "aws_managed": False, "attachment_count": 1,
                      "document": {"Version": "2012-10-17", "Statement": [
                          {"Sid": "Compute", "Effect": "Allow", "Action": ["ec2:*", "lambda:*"], "Resource": "*"},
                          {"Sid": "Logs", "Effect": "Allow", "Action": ["logs:Get*", "logs:Describe*"], "Resource": "*"}]}},
            READ_ARN: {"name": "AppReadOnly", "aws_managed": False, "attachment_count": 3,
                       "document": {"Version": "2012-10-17", "Statement": [
                           {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"]}]}},
        },
        "credential_report": [
            cred("<root_account>", f"arn:aws:iam::{ACC}:root", True, False, 10, k1=(500, 20), created=1500),
            cred("alice", f"arn:aws:iam::{ACC}:user/alice", True, False, 1, k1=(400, 3)),
            cred("bob", f"arn:aws:iam::{ACC}:user/bob", False, False, None, k1=(200, None), k2=(10, 1)),
            cred("ci-deploy", f"arn:aws:iam::{ACC}:user/ci-deploy", False, False, None, k1=(380, 150)),
            cred("carol", f"arn:aws:iam::{ACC}:user/carol", True, True, 210),
        ],
        "access_analyzer": {"analyzers": ["account-analyzer"], "findings": [
            {"id": "f-1", "resource": "arn:aws:s3:::public-assets-demo", "resource_type": "AWS::S3::Bucket",
             "is_public": True, "finding_type": "ExternalAccess", "principal": "*", "analyzer": "account-analyzer"}]},
        "advisor": {
            f"arn:aws:iam::{ACC}:group/Admins": [
                {"service_namespace": "iam", "last_authenticated": ago(5), "actions": [{"name": "ListUsers", "last_accessed": ago(5)}]},
                {"service_namespace": "s3", "last_authenticated": ago(2), "actions": [{"name": "ListAllMyBuckets", "last_accessed": ago(2)}]},
                {"service_namespace": "ec2", "last_authenticated": ago(500), "actions": []}],
            f"arn:aws:iam::{ACC}:role/LegacyAdminRole": [{"service_namespace": "s3", "last_authenticated": ago(400), "actions": []}],
            f"arn:aws:iam::{ACC}:user/bob": [
                {"service_namespace": "s3", "last_authenticated": ago(30), "actions": []},
                {"service_namespace": "ec2", "last_authenticated": ago(20), "actions": []}],
        },
    }
