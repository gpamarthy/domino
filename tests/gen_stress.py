#!/usr/bin/env python3
"""
Generate a large realistic AWS snapshot for stress-testing domino's chain finder.

Account 111222333444 with:
- 10 IAM users, 80 roles (5 admin), 5 S3 buckets, 10 EC2, 10 Lambda
- 20 role-to-role trust chains (depth 2-4)
- Confused deputy: public S3 -> Lambda trigger -> privileged role -> admin
- 10+ distinct exploit chains from various starting points
"""

import json
import os

ACCT = "111222333444"
REGION = "us-east-1"


def arn(kind, name, service=None):
    if kind == "role":
        return f"arn:aws:iam::{ACCT}:role/{name}"
    if kind == "user":
        return f"arn:aws:iam::{ACCT}:user/{name}"
    if kind == "profile":
        return f"arn:aws:iam::{ACCT}:instance-profile/{name}"
    if kind == "lambda":
        return f"arn:aws:lambda:{REGION}:{ACCT}:function:{name}"
    if kind == "root":
        return f"arn:aws:iam::{ACCT}:root"
    return name


def trust_doc(principals):
    """Build AssumeRolePolicyDocument trusting given ARNs or services."""
    aws_princs = []
    svc_princs = []
    for p in principals:
        if p.endswith(".amazonaws.com"):
            svc_princs.append(p)
        else:
            aws_princs.append(p)

    stmts = []
    if aws_princs:
        val = aws_princs[0] if len(aws_princs) == 1 else aws_princs
        stmts.append({"Effect": "Allow", "Principal": {"AWS": val}, "Action": "sts:AssumeRole"})
    if svc_princs:
        val = svc_princs[0] if len(svc_princs) == 1 else svc_princs
        stmts.append({"Effect": "Allow", "Principal": {"Service": val}, "Action": "sts:AssumeRole"})

    return {"Version": "2012-10-17", "Statement": stmts}


def inline_policy(name, statements):
    return {
        "PolicyName": name,
        "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
    }


def stmt(sid, actions, resources, effect="Allow"):
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return {"Sid": sid, "Effect": effect, "Action": actions, "Resource": resources}


def admin_policy():
    return inline_policy(
        "full-admin", [{"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}]
    )


def make_role(name, trust_principals, policies=None, managed=None, instance_profiles=None):
    rid = name.upper().replace("-", "")[:18]
    r = {
        "RoleName": name,
        "Arn": arn("role", name),
        "RoleId": f"AROA{rid:>016s}"[:20],
        "CreateDate": "2025-09-01T08:00:00Z",
        "Path": "/",
        "AssumeRolePolicyDocument": trust_doc(trust_principals),
        "RolePolicyList": policies or [],
        "AttachedManagedPolicies": managed or [],
        "InstanceProfileList": instance_profiles or [],
    }
    return r


def make_user(name, policies=None, managed=None, groups=None):
    uid = name.upper().replace("-", "")[:16]
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserId": f"AIDA{uid:>016s}"[:20],
        "CreateDate": "2025-08-15T09:00:00Z",
        "Path": "/",
        "GroupList": groups or [],
        "AttachedManagedPolicies": managed or [],
        "UserPolicyList": policies or [],
    }


def make_ec2(instance_id, profile_arn, profile_id, imds_v1, tag_name):
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.medium",
        "State": {"Name": "running", "Code": 16},
        "IamInstanceProfile": {"Arn": profile_arn, "Id": profile_id},
        "MetadataOptions": {
            "HttpTokens": "optional" if imds_v1 else "required",
            "HttpEndpoint": "enabled",
            "HttpPutResponseHopLimit": 1,
        },
        "Tags": [{"Key": "Name", "Value": tag_name}],
    }


def make_lambda(fn_name, role_name, s3_triggers=None):
    return {
        "FunctionName": fn_name,
        "FunctionArn": arn("lambda", fn_name),
        "Runtime": "python3.12",
        "Role": arn("role", role_name),
        "Handler": "index.handler",
        "CodeSize": 4096,
        "Timeout": 300,
        "MemorySize": 256,
        "LastModified": "2025-10-01T14:00:00.000+0000",
        "S3Triggers": [{"Bucket": b} for b in (s3_triggers or [])],
        "EventSourceMappings": [],
    }


def make_bucket(name, public=False):
    b = {"Name": name, "ACL": None}
    if public:
        b["PublicAccessBlock"] = None
        b["Policy"] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicAccess",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:PutObject", "s3:GetObject"],
                    "Resource": f"arn:aws:s3:::{name}/*",
                }
            ],
        }
    else:
        b["PublicAccessBlock"] = {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
        b["Policy"] = None
    return b


def build():
    roles = []
    users = []
    buckets = []
    ec2s = []
    lambdas = []

    root = arn("root", "")

    # =========================================================================
    # 5 ADMIN ROLES
    # =========================================================================
    admin_names = [
        "org-admin-role",
        "break-glass-admin",
        "infra-terraform-admin",
        "security-incident-admin",
        "platform-superadmin",
    ]
    for nm in admin_names:
        roles.append(make_role(nm, [root], policies=[admin_policy()]))

    # =========================================================================
    # 20 CHAIN ROLES (trust other roles, creating depth 2-4 chains to admin)
    # =========================================================================

    # --- Chain group A: depth 2 (role -> admin) ---
    # 4 roles that can directly assume an admin role
    chain_a = [
        ("ci-deploy-role", "org-admin-role"),
        ("db-migration-runner", "break-glass-admin"),
        ("release-manager-role", "infra-terraform-admin"),
        ("cost-optimizer-role", "security-incident-admin"),
    ]
    for nm, target_admin in chain_a:
        roles.append(
            make_role(
                nm,
                [root],
                policies=[
                    inline_policy(
                        "chain-up", [stmt("Chain", "sts:AssumeRole", arn("role", target_admin))]
                    )
                ],
            )
        )
    # admin roles need to trust these chain roles
    for i, (nm, target_admin) in enumerate(chain_a):
        for r in roles:
            if r["RoleName"] == target_admin:
                existing = r["AssumeRolePolicyDocument"]["Statement"]
                existing.append(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn("role", nm)},
                        "Action": "sts:AssumeRole",
                    }
                )

    # --- Chain group B: depth 3 (role -> intermediate -> admin) ---
    chain_b = [
        ("data-pipeline-role", "ci-deploy-role"),
        ("ml-training-role", "db-migration-runner"),
        ("log-processor-role", "release-manager-role"),
        ("etl-scheduler-role", "cost-optimizer-role"),
        ("report-generator-role", "ci-deploy-role"),
        ("backup-rotation-role", "db-migration-runner"),
    ]
    for nm, target in chain_b:
        roles.append(
            make_role(
                nm,
                [root],
                policies=[
                    inline_policy(
                        "chain-up", [stmt("Chain", "sts:AssumeRole", arn("role", target))]
                    )
                ],
            )
        )
    for nm, target in chain_b:
        for r in roles:
            if r["RoleName"] == target:
                existing = r["AssumeRolePolicyDocument"]["Statement"]
                existing.append(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn("role", nm)},
                        "Action": "sts:AssumeRole",
                    }
                )

    # --- Chain group C: depth 4 (role -> B -> A -> admin) ---
    chain_c = [
        ("event-bridge-processor", "data-pipeline-role"),
        ("sqs-consumer-role", "ml-training-role"),
        ("cloudwatch-alerter", "log-processor-role"),
        ("kinesis-ingest-role", "etl-scheduler-role"),
        ("glue-crawler-role", "report-generator-role"),
        ("step-function-exec", "backup-rotation-role"),
    ]
    for nm, target in chain_c:
        roles.append(
            make_role(
                nm,
                [root],
                policies=[
                    inline_policy(
                        "chain-up", [stmt("Chain", "sts:AssumeRole", arn("role", target))]
                    )
                ],
            )
        )
    for nm, target in chain_c:
        for r in roles:
            if r["RoleName"] == target:
                existing = r["AssumeRolePolicyDocument"]["Statement"]
                existing.append(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn("role", nm)},
                        "Action": "sts:AssumeRole",
                    }
                )

    # =========================================================================
    # 10 EC2 ROLES (5 IMDSv1, 5 IMDSv2)
    # =========================================================================
    ec2_role_names_v1 = [
        "web-frontend-role",
        "api-gateway-role",
        "batch-worker-role",
        "legacy-monolith-role",
        "staging-app-role",
    ]
    ec2_role_names_v2 = [
        "hardened-api-role",
        "prod-backend-role",
        "internal-tooling-role",
        "monitoring-agent-role",
        "vault-proxy-role",
    ]

    # IMDSv1 roles can assume chain roles that lead to admin
    imdsv1_targets = [
        "data-pipeline-role",  # depth 3 -> ci-deploy -> org-admin
        "ml-training-role",  # depth 3 -> db-migration -> break-glass
        "event-bridge-processor",  # depth 4
        "ci-deploy-role",  # depth 2 -> org-admin
        "release-manager-role",  # depth 2 -> infra-terraform-admin
    ]
    for i, nm in enumerate(ec2_role_names_v1):
        target = imdsv1_targets[i]
        roles.append(
            make_role(
                nm,
                ["ec2.amazonaws.com"],
                policies=[
                    inline_policy(
                        "assume-chain", [stmt("Assume", "sts:AssumeRole", arn("role", target))]
                    )
                ],
            )
        )
        # target must trust this role
        for r in roles:
            if r["RoleName"] == target:
                existing = r["AssumeRolePolicyDocument"]["Statement"]
                existing.append(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn("role", nm)},
                        "Action": "sts:AssumeRole",
                    }
                )

    # IMDSv2 roles -- limited permissions, no chain to admin
    for nm in ec2_role_names_v2:
        roles.append(
            make_role(
                nm,
                ["ec2.amazonaws.com"],
                policies=[
                    inline_policy(
                        "read-only",
                        [stmt("ReadLogs", ["logs:GetLogEvents", "logs:DescribeLogGroups"], "*")],
                    )
                ],
            )
        )

    # Build instance profiles and EC2 instances
    all_ec2_roles = ec2_role_names_v1 + ec2_role_names_v2
    ec2_tags_v1 = [
        "web-prod-01",
        "api-prod-01",
        "batch-worker-01",
        "legacy-app-01",
        "staging-app-01",
    ]
    ec2_tags_v2 = [
        "hardened-api-01",
        "prod-backend-01",
        "internal-tools-01",
        "mon-agent-01",
        "vault-proxy-01",
    ]
    ec2_tags = ec2_tags_v1 + ec2_tags_v2

    for i, rname in enumerate(all_ec2_roles):
        prof_name = f"{rname}-profile"
        prof_arn_str = arn("profile", prof_name)
        prof_id = f"AIPA{rname.upper().replace('-', '')[:14]:>014s}"[:18]

        ip = {
            "InstanceProfileName": prof_name,
            "InstanceProfileId": prof_id,
            "Arn": prof_arn_str,
            "Path": "/",
            "Roles": [{"RoleName": rname, "Arn": arn("role", rname)}],
            "CreateDate": "2025-09-01T08:00:00Z",
        }
        # attach profile to the role
        for r in roles:
            if r["RoleName"] == rname:
                r["InstanceProfileList"] = [ip]

        iid = f"i-{i:04d}{rname.replace('-', '')[:8]}"
        is_v1 = i < 5
        ec2s.append(make_ec2(iid, prof_arn_str, prof_id, is_v1, ec2_tags[i]))

    # =========================================================================
    # 10 LAMBDA EXECUTION ROLES
    # =========================================================================
    lambda_role_specs = [
        # (role_name, chains_to, trusted_by_service)
        # These chain to admin through 1-2 hops
        ("ingest-processor-exec", "ci-deploy-role"),  # 1 hop -> org-admin
        ("etl-transform-exec", "db-migration-runner"),  # 1 hop -> break-glass
        ("notification-handler-exec", "data-pipeline-role"),  # 2 hops
        ("image-resizer-exec", "ml-training-role"),  # 2 hops
        ("auth-validator-exec", "release-manager-role"),  # 1 hop -> infra-terraform
        ("pdf-generator-exec", "cost-optimizer-role"),  # 1 hop -> security-incident
        ("webhook-relay-exec", "log-processor-role"),  # 2 hops
        ("slack-notifier-exec", "etl-scheduler-role"),  # 2 hops
        ("audit-log-shipper-exec", "event-bridge-processor"),  # 3 hops
        ("s3-janitor-exec", "sqs-consumer-role"),  # 3 hops
    ]

    for rname, target in lambda_role_specs:
        roles.append(
            make_role(
                rname,
                ["lambda.amazonaws.com"],
                policies=[
                    inline_policy(
                        "chain-assume", [stmt("Chain", "sts:AssumeRole", arn("role", target))]
                    )
                ],
            )
        )
        for r in roles:
            if r["RoleName"] == target:
                existing = r["AssumeRolePolicyDocument"]["Statement"]
                existing.append(
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": arn("role", rname)},
                        "Action": "sts:AssumeRole",
                    }
                )

    # =========================================================================
    # 10 LAMBDA FUNCTIONS
    # =========================================================================
    lambda_fn_specs = [
        ("ingest-processor", "ingest-processor-exec", ["analytics-exports"]),
        ("etl-transform", "etl-transform-exec", []),
        ("notification-handler", "notification-handler-exec", []),
        ("image-resizer", "image-resizer-exec", ["ml-training-data"]),
        ("auth-validator", "auth-validator-exec", []),
        ("pdf-generator", "pdf-generator-exec", []),
        ("webhook-relay", "webhook-relay-exec", []),
        ("slack-notifier", "slack-notifier-exec", []),
        ("audit-log-shipper", "audit-log-shipper-exec", []),
        ("s3-janitor", "s3-janitor-exec", ["compliance-reports"]),
    ]
    for fn_name, role_name, triggers in lambda_fn_specs:
        lambdas.append(make_lambda(fn_name, role_name, s3_triggers=triggers))

    # =========================================================================
    # 5 S3 BUCKETS (2 public, 3 private)
    # =========================================================================
    # Public buckets -- confused deputy attack surface
    buckets.append(make_bucket("analytics-exports", public=True))
    buckets.append(make_bucket("ml-training-data", public=True))
    # Private buckets
    buckets.append(make_bucket("compliance-reports", public=False))
    buckets.append(make_bucket("prod-database-backups", public=False))
    buckets.append(make_bucket("internal-artifacts", public=False))

    # =========================================================================
    # FILLER ROLES (to reach 80 total)
    # =========================================================================
    # 5 admin + 4 chain-A + 6 chain-B + 6 chain-C + 10 ec2 + 10 lambda exec = 41
    # Need 39 more filler roles with no escalation paths
    filler_names = [
        "cloudfront-origin-access",
        "ses-email-sender",
        "sns-publisher-role",
        "dynamodb-stream-handler",
        "rds-monitoring-role",
        "ecs-task-exec-role",
        "codebuild-runner",
        "codepipeline-exec",
        "config-recorder-role",
        "guardduty-detector-role",
        "inspector-scan-role",
        "macie-classifier-role",
        "access-analyzer-role",
        "waf-logging-role",
        "shield-responder-role",
        "organizations-readonly",
        "sso-permission-set-a",
        "sso-permission-set-b",
        "transfer-family-role",
        "datasync-agent-role",
        "appflow-connector-role",
        "eventbridge-scheduler-role",
        "iot-device-shadow-role",
        "iot-rules-engine-role",
        "sagemaker-notebook-role",
        "comprehend-analysis-role",
        "textract-processor-role",
        "rekognition-face-role",
        "transcribe-medical-role",
        "polly-speech-role",
        "lex-bot-runtime-role",
        "kendra-index-role",
        "personalize-campaign-role",
        "forecast-predictor-role",
        "fraud-detector-role",
        "lookout-metrics-role",
        "healthlake-store-role",
        "timestream-writer-role",
        "neptune-loader-role",
    ]

    for nm in filler_names:
        roles.append(
            make_role(
                nm,
                [root],
                policies=[
                    inline_policy(
                        "read-only",
                        [
                            stmt(
                                "ReadOnly",
                                [
                                    "s3:GetObject",
                                    "s3:ListBucket",
                                    "logs:GetLogEvents",
                                    "cloudwatch:GetMetricData",
                                ],
                                "*",
                            )
                        ],
                    )
                ],
            )
        )

    # =========================================================================
    # 10 IAM USERS with varied permissions
    # =========================================================================
    user_specs = [
        # (name, policies_list)
        # 1. dev-intern: PassRole * + Lambda create/invoke -> can use any Lambda role
        (
            "dev-intern",
            [
                inline_policy(
                    "dev-permissions",
                    [
                        stmt("PassRole", "iam:PassRole", "*"),
                        stmt("LambdaOps", ["lambda:CreateFunction", "lambda:InvokeFunction"], "*"),
                        stmt(
                            "AssumeStagingRole", "sts:AssumeRole", arn("role", "data-pipeline-role")
                        ),
                    ],
                )
            ],
        ),
        # 2. sre-oncall: AssumeRole to break-glass-admin (direct)
        (
            "sre-oncall",
            [
                inline_policy(
                    "oncall-perms",
                    [
                        stmt("BreakGlass", "sts:AssumeRole", arn("role", "break-glass-admin")),
                        stmt("ReadAll", ["s3:GetObject", "logs:GetLogEvents"], "*"),
                    ],
                )
            ],
        ),
        # 3. data-analyst: AssumeRole to ml-training-role (chain: ml-training -> db-migration -> break-glass)
        (
            "data-analyst",
            [
                inline_policy(
                    "analyst-perms",
                    [
                        stmt("AssumeML", "sts:AssumeRole", arn("role", "ml-training-role")),
                        stmt(
                            "AthenaQuery",
                            ["athena:StartQueryExecution", "athena:GetQueryResults"],
                            "*",
                        ),
                    ],
                )
            ],
        ),
        # 4. ci-bot: AssumeRole to ci-deploy-role (chain: ci-deploy -> org-admin)
        (
            "ci-bot",
            [
                inline_policy(
                    "ci-perms",
                    [
                        stmt("AssumeDeploy", "sts:AssumeRole", arn("role", "ci-deploy-role")),
                        stmt("ECR", ["ecr:GetAuthorizationToken", "ecr:BatchGetImage"], "*"),
                    ],
                )
            ],
        ),
        # 5. platform-eng: iam:AttachUserPolicy self-escalation
        (
            "platform-eng",
            [
                inline_policy(
                    "platform-perms",
                    [
                        stmt("SelfEscalate", "iam:AttachUserPolicy", "*"),
                        stmt(
                            "DescribeInfra",
                            [
                                "ec2:DescribeInstances",
                                "rds:DescribeDBInstances",
                                "ecs:DescribeClusters",
                            ],
                            "*",
                        ),
                    ],
                )
            ],
        ),
        # 6. security-auditor: AssumeRole to many chain roles
        (
            "security-auditor",
            [
                inline_policy(
                    "audit-perms",
                    [
                        stmt(
                            "AssumeAuditRoles",
                            "sts:AssumeRole",
                            [
                                arn("role", "log-processor-role"),
                                arn("role", "cloudwatch-alerter"),
                            ],
                        ),
                        stmt(
                            "ReadSecLogs",
                            [
                                "guardduty:GetFindings",
                                "securityhub:GetFindings",
                                "config:GetComplianceDetailsByConfigRule",
                            ],
                            "*",
                        ),
                    ],
                )
            ],
        ),
        # 7. backend-dev: PassRole + EC2 RunInstances -> privilege escalation via EC2
        (
            "backend-dev",
            [
                inline_policy(
                    "backend-perms",
                    [
                        stmt("PassRole", "iam:PassRole", "*"),
                        stmt("EC2Ops", "ec2:RunInstances", "*"),
                        stmt(
                            "CodeBuild", ["codebuild:StartBuild", "codebuild:BatchGetBuilds"], "*"
                        ),
                    ],
                )
            ],
        ),
        # 8. ml-engineer: AssumeRole to sagemaker + chain to admin
        (
            "ml-engineer",
            [
                inline_policy(
                    "ml-perms",
                    [
                        stmt("AssumeML", "sts:AssumeRole", arn("role", "event-bridge-processor")),
                        stmt(
                            "SageMaker",
                            ["sagemaker:CreateTrainingJob", "sagemaker:DescribeEndpoint"],
                            "*",
                        ),
                    ],
                )
            ],
        ),
        # 9. devops-lead: iam:PutRolePolicy self-escalation + lambda:UpdateFunctionCode
        (
            "devops-lead",
            [
                inline_policy(
                    "devops-perms",
                    [
                        stmt("PolicyManip", "iam:PutRolePolicy", "*"),
                        stmt("LambdaHijack", "lambda:UpdateFunctionCode", "*"),
                        stmt(
                            "CloudFormation",
                            ["cloudformation:CreateStack", "cloudformation:DescribeStacks"],
                            "*",
                        ),
                    ],
                )
            ],
        ),
        # 10. finance-readonly: limited permissions, but AssumeRole to cost-optimizer (chain to admin)
        (
            "finance-readonly",
            [
                inline_policy(
                    "finance-perms",
                    [
                        stmt("AssumeCost", "sts:AssumeRole", arn("role", "cost-optimizer-role")),
                        stmt("Billing", ["ce:GetCostAndUsage", "budgets:DescribeBudgets"], "*"),
                    ],
                )
            ],
        ),
    ]

    for uname, policies in user_specs:
        users.append(make_user(uname, policies=policies))

    # --- Make sure account-root-trusting roles also trust users via root principal ---
    # The root trust already covers users in this account (domino's _trust_allows handles this)

    # =========================================================================
    # ASSEMBLE SNAPSHOT
    # =========================================================================
    snapshot = {
        "account_id": ACCT,
        "iam": {
            "users": users,
            "roles": roles,
            "groups": [],
            "policy_docs": {
                "arn:aws:iam::aws:policy/AdministratorAccess": {
                    "v1": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                    }
                }
            },
        },
        "s3": {"buckets": buckets},
        "ec2": {"instances": ec2s},
        "lambda": {"functions": lambdas},
    }

    return snapshot


def main():
    snapshot = build()

    out_dir = os.path.join(os.path.dirname(__file__), "snapshots")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "stress_test.json")

    with open(out_path, "w") as f:
        json.dump(snapshot, f, indent=2)

    n_roles = len(snapshot["iam"]["roles"])
    n_users = len(snapshot["iam"]["users"])
    n_buckets = len(snapshot["s3"]["buckets"])
    n_ec2 = len(snapshot["ec2"]["instances"])
    n_lambdas = len(snapshot["lambda"]["functions"])

    print(f"[+] Generated stress test snapshot: {out_path}")
    print(
        f"    Users: {n_users}  Roles: {n_roles}  Buckets: {n_buckets}  EC2: {n_ec2}  Lambda: {n_lambdas}"
    )
    print("    Admin roles: 5")
    print("    Role chains: 20 (depths 2-4)")
    print("    Public buckets with Lambda triggers: 2 (confused deputy)")


if __name__ == "__main__":
    main()
