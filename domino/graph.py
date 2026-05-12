import fnmatch
import json

import networkx as nx

# edge types -- plain strings, not an enum
ASSUME = "assume_role"
PASSROLE = "pass_role"
USES_ROLE = "uses_role"
S3_TRIGGER = "s3_trigger"
IMDS_STEAL = "imds_creds"
CREATE_ATTACH = "create"  # compound: passrole + create function/instance
IAM_ESCALATE = "iam_escalate"  # can self-grant admin via IAM policy manipulation
LAMBDA_HIJACK = "lambda_hijack"  # can update existing Lambda code to steal its role

# weight = exploitation difficulty (0=structural, 1=easy, 2=moderate, 3=hard)
WEIGHTS = {
    ASSUME: 1,
    PASSROLE: 2,
    USES_ROLE: 0,
    S3_TRIGGER: 1,
    IMDS_STEAL: 1,
    CREATE_ATTACH: 2,
    IAM_ESCALATE: 1,  # one API call to admin
    LAMBDA_HIJACK: 2,
}


def build_graph(data):
    g = nx.MultiDiGraph()

    _add_iam_nodes(g, data["iam"])

    # s3 and ec2 nodes are simple enough to inline
    for b in data["s3"]["buckets"]:
        nid = f"s3:{b['Name']}"
        g.add_node(nid, kind="s3", name=b["Name"], public=_is_public_bucket(b), raw=b)

    for inst in data["ec2"]["instances"]:
        iid = inst["InstanceId"]
        # Capital One pattern -- IMDSv1 means creds are one SSRF away
        md = inst.get("MetadataOptions", {})
        v1 = md.get("HttpTokens", "optional") == "optional"
        g.add_node(f"ec2:{iid}", kind="ec2", imds_v1=v1, raw=inst)

    for fn in data["lambda"]["functions"]:
        g.add_node(fn["FunctionArn"], kind="lambda", name=fn["FunctionName"], raw=fn)

    _link_iam(g, data["iam"])
    _link_s3_policies(g, data)
    _link_ec2_profiles(g, data)
    _link_lambda_roles(g, data)
    _link_cross_service(g, data)

    return g


def _add_iam_nodes(g, iam):
    for u in iam["users"]:
        arn = u.get("Arn") or u.get("arn")
        g.add_node(arn, kind="user", name=u.get("UserName", ""), raw=u)

    for r in iam["roles"]:
        arn = r.get("Arn") or r.get("arn")
        adm = _is_admin(r, iam.get("policy_docs", {}))
        g.add_node(arn, kind="role", name=r.get("RoleName", ""), admin=adm, raw=r)


def _link_iam(g, iam):
    # user -> role edges
    for u in iam["users"]:
        u_arn = u.get("Arn") or u.get("arn")
        stmts = _effective_stmts(u, iam)

        for r in iam["roles"]:
            r_arn = r.get("Arn") or r.get("arn")

            if _trust_allows(u_arn, r) and _grants(stmts, "sts:AssumeRole", r_arn):
                g.add_edge(
                    u_arn,
                    r_arn,
                    kind=ASSUME,
                    weight=WEIGHTS[ASSUME],
                    desc=f"assume {r.get('RoleName', '')}",
                )

            if _grants(stmts, "iam:PassRole", r_arn):
                g.add_edge(
                    u_arn,
                    r_arn,
                    kind=PASSROLE,
                    weight=WEIGHTS[PASSROLE],
                    desc=f"pass {r.get('RoleName', '')}",
                )

    # role -> role chains
    for r1 in iam["roles"]:
        r1_arn = r1.get("Arn") or r1.get("arn")
        stmts = _role_stmts(r1, iam)

        for r2 in iam["roles"]:
            r2_arn = r2.get("Arn") or r2.get("arn")
            if r1_arn == r2_arn:
                continue

            if _trust_allows(r1_arn, r2) and _grants(stmts, "sts:AssumeRole", r2_arn):
                g.add_edge(r1_arn, r2_arn, kind=ASSUME, weight=WEIGHTS[ASSUME], desc="role chain")

            if _grants(stmts, "iam:PassRole", r2_arn):
                g.add_edge(
                    r1_arn, r2_arn, kind=PASSROLE, weight=WEIGHTS[PASSROLE], desc="pass from role"
                )


def _link_s3_policies(g, data):
    for b in data["s3"]["buckets"]:
        node = f"s3:{b['Name']}"
        pol = b.get("Policy")
        if not pol:
            continue
        if isinstance(pol, str):
            pol = json.loads(pol)

        for stmt in pol.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            for p in _principals(stmt):
                src = p
                if p == "*":
                    src = "anyone"
                    if "anyone" not in g:
                        g.add_node("anyone", kind="external", name="Public/Anonymous")
                if src in g:
                    g.add_edge(src, node, kind="s3_access", weight=1, desc="bucket policy grant")


def _link_ec2_profiles(g, data):
    for inst in data["ec2"]["instances"]:
        iid = inst["InstanceId"]
        ec2_node = f"ec2:{iid}"

        prof = inst.get("IamInstanceProfile", {})
        if not prof:
            continue

        prof_arn = prof.get("Arn", "")

        for r in data["iam"]["roles"]:
            r_arn = r.get("Arn") or r.get("arn")

            if not _service_trusted(r, "ec2.amazonaws.com"):
                continue

            # match instance profile to role
            for ip in r.get("InstanceProfileList", []):
                if ip.get("Arn") == prof_arn:
                    g.add_edge(ec2_node, r_arn, kind=USES_ROLE, weight=WEIGHTS[USES_ROLE])

                    if g.nodes[ec2_node].get("imds_v1"):
                        g.add_edge(
                            ec2_node,
                            r_arn,
                            kind=IMDS_STEAL,
                            weight=WEIGHTS[IMDS_STEAL],
                            desc="IMDSv1 credential theft",
                        )
                    break


def _link_lambda_roles(g, data):
    for fn in data["lambda"]["functions"]:
        fn_arn = fn["FunctionArn"]
        role_arn = fn.get("Role", "")
        if role_arn and role_arn in g:
            g.add_edge(fn_arn, role_arn, kind=USES_ROLE, weight=WEIGHTS[USES_ROLE])

        # s3 notification config -> lambda trigger
        # these come through as notification configs, not ESMs
        for trigger in fn.get("S3Triggers", []):
            bkt = trigger.get("Bucket", "")
            s3_node = f"s3:{bkt}"
            if s3_node in g:
                g.add_edge(
                    s3_node,
                    fn_arn,
                    kind=S3_TRIGGER,
                    weight=WEIGHTS[S3_TRIGGER],
                    desc="S3 event triggers Lambda",
                )

        # also check event source mappings
        for esm in fn.get("EventSourceMappings", []):
            src = esm.get("EventSourceArn", "")
            if ":s3" in src:
                bkt = src.split(":::")[-1] if ":::" in src else ""
                s3_node = f"s3:{bkt}"
                if s3_node in g:
                    g.add_edge(
                        s3_node,
                        fn_arn,
                        kind=S3_TRIGGER,
                        weight=WEIGHTS[S3_TRIGGER],
                        desc="S3 event source mapping",
                    )


# this is where domino earns its name -- these edges don't exist in other tools


def _link_cross_service(g, data):
    iam = data["iam"]

    # check both users and roles as potential attackers
    principals = [(u, _effective_stmts(u, iam)) for u in iam["users"]]
    principals += [(r, _role_stmts(r, iam)) for r in iam["roles"]]

    for princ, stmts in principals:
        p_arn = princ.get("Arn") or princ.get("arn")

        for r in iam["roles"]:
            r_arn = r.get("Arn") or r.get("arn")
            if p_arn == r_arn:
                continue

            if not _grants(stmts, "iam:PassRole", r_arn):
                continue

            # passrole + lambda:create + lambda:invoke = full escalation
            if _grants(stmts, "lambda:CreateFunction", "*") and _grants(
                stmts, "lambda:InvokeFunction", "*"
            ):
                g.add_edge(
                    p_arn,
                    r_arn,
                    kind=CREATE_ATTACH,
                    weight=WEIGHTS[CREATE_ATTACH],
                    desc="PassRole+Lambda escalation",
                )

            # passrole + ec2:runinstances
            if _grants(stmts, "ec2:RunInstances", "*"):
                g.add_edge(
                    p_arn, r_arn, kind=CREATE_ATTACH, weight=3, desc="PassRole+EC2 escalation"
                )

            # passrole + glue:CreateDevEndpoint -- ssh into dev endpoint with the role
            if _grants(stmts, "glue:CreateDevEndpoint", "*"):
                g.add_edge(
                    p_arn,
                    r_arn,
                    kind=CREATE_ATTACH,
                    weight=WEIGHTS[CREATE_ATTACH],
                    desc="PassRole+Glue escalation",
                )

            # passrole + cloudformation:CreateStack -- CFN executes as the passed role
            if _grants(stmts, "cloudformation:CreateStack", "*"):
                g.add_edge(
                    p_arn,
                    r_arn,
                    kind=CREATE_ATTACH,
                    weight=WEIGHTS[CREATE_ATTACH],
                    desc="PassRole+CloudFormation escalation",
                )

            # passrole + sagemaker:CreateNotebookInstance -- jupyter shell as the role
            if _grants(stmts, "sagemaker:CreateNotebookInstance", "*"):
                g.add_edge(
                    p_arn,
                    r_arn,
                    kind=CREATE_ATTACH,
                    weight=WEIGHTS[CREATE_ATTACH],
                    desc="PassRole+SageMaker escalation",
                )

            # passrole + codebuild:CreateProject -- build container runs as the role
            if _grants(stmts, "codebuild:CreateProject", "*"):
                g.add_edge(
                    p_arn,
                    r_arn,
                    kind=CREATE_ATTACH,
                    weight=WEIGHTS[CREATE_ATTACH],
                    desc="PassRole+CodeBuild escalation",
                )

    # IAM self-escalation: if a principal can modify its own (or others') policies,
    # it can grant itself admin. this is the #1 privesc path in IAM Vulnerable.
    # ref: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
    _link_iam_escalation(g, iam)
    _link_lambda_hijack(g, data)


def _link_iam_escalation(g, iam):
    # IAM actions that let you self-escalate to admin
    escalation_actions = [
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AddUserToGroup",
        "iam:AttachGroupPolicy",
        "iam:PutGroupPolicy",
    ]

    principals = [(u, _effective_stmts(u, iam)) for u in iam["users"]]
    principals += [(r, _role_stmts(r, iam)) for r in iam["roles"]]

    for princ, stmts in principals:
        p_arn = princ.get("Arn") or princ.get("arn")
        for action in escalation_actions:
            if _grants(stmts, action, "*"):
                # this principal can self-escalate
                # model as edge from principal to a synthetic "admin" target
                # but actually -- the real target is themselves becoming admin.
                # create a self-loop to mark this principal as "can become admin"
                g.add_edge(
                    p_arn,
                    p_arn,
                    kind=IAM_ESCALATE,
                    weight=WEIGHTS[IAM_ESCALATE],
                    desc=f"{action.split(':')[1]} self-escalation",
                )
                break  # one escalation action is enough, don't spam edges


def _link_lambda_hijack(g, data):
    # if a principal can UpdateFunctionCode on an existing Lambda,
    # they effectively get that Lambda's execution role
    iam = data["iam"]
    principals = [(u, _effective_stmts(u, iam)) for u in iam["users"]]
    principals += [(r, _role_stmts(r, iam)) for r in iam["roles"]]

    for princ, stmts in principals:
        p_arn = princ.get("Arn") or princ.get("arn")
        if not _grants(stmts, "lambda:UpdateFunctionCode", "*"):
            continue

        for fn in data["lambda"]["functions"]:
            fn_arn = fn["FunctionArn"]
            role_arn = fn.get("Role", "")
            if role_arn and role_arn in g:
                # can hijack this Lambda -> gets its role
                g.add_edge(
                    p_arn,
                    fn_arn,
                    kind=LAMBDA_HIJACK,
                    weight=WEIGHTS[LAMBDA_HIJACK],
                    desc=f"hijack {fn['FunctionName']} code",
                )


# -- IAM helpers


def _is_admin(role, pdocs):
    for p in role.get("AttachedManagedPolicies", []):
        if "AdministratorAccess" in p.get("PolicyArn", ""):
            return True

    for p in role.get("RolePolicyList", []):
        if _doc_is_admin(p.get("PolicyDocument", {})):
            return True

    for p in role.get("AttachedManagedPolicies", []):
        arn = p.get("PolicyArn", "")
        for vid, doc in pdocs.get(arn, {}).items():
            if _doc_is_admin(doc):
                return True

    return False


def _doc_is_admin(doc):
    for s in doc.get("Statement", []):
        if s.get("Effect") != "Allow":
            continue
        acts = s.get("Action", [])
        res = s.get("Resource", [])
        if isinstance(acts, str):
            acts = [acts]
        if isinstance(res, str):
            res = [res]
        if "*" in acts and "*" in res:
            return True
    return False


def _is_public_bucket(b):
    pab = b.get("PublicAccessBlock")
    if pab:
        blocked = all(
            pab.get(k)
            for k in [
                "BlockPublicAcls",
                "BlockPublicPolicy",
                "IgnorePublicAcls",
                "RestrictPublicBuckets",
            ]
        )
        if blocked:
            return False

    pol = b.get("Policy")
    if pol:
        if isinstance(pol, str):
            pol = json.loads(pol)
        for s in pol.get("Statement", []):
            if s.get("Effect") == "Allow" and "*" in _principals(s):
                return True
    return False


def _trust_allows(caller_arn, role):
    trust = role.get("AssumeRolePolicyDocument", {})
    for s in trust.get("Statement", []):
        if s.get("Effect") != "Allow":
            continue
        act = s.get("Action", "")
        if isinstance(act, list):
            if "sts:AssumeRole" not in act:
                continue
        elif act != "sts:AssumeRole":
            continue

        for p in _principals(s):
            if p == "*":
                return True
            if fnmatch.fnmatch(caller_arn, p):
                return True
            # account-level trust: arn:aws:iam::123456:root
            if p.endswith(":root"):
                prefix = p.rsplit(":root", 1)[0]
                if caller_arn.startswith(prefix):
                    return True
    return False


def _service_trusted(role, service):
    trust = role.get("AssumeRolePolicyDocument", {})
    for s in trust.get("Statement", []):
        if s.get("Effect") != "Allow":
            continue
        if service in _principals(s):
            return True
    return False


def _principals(stmt):
    p = stmt.get("Principal", {})
    if isinstance(p, str):
        return [p]
    out = []
    for k in ("AWS", "Service", "Federated"):
        v = p.get(k, [])
        if isinstance(v, str):
            out.append(v)
        else:
            out.extend(v)
    return out


def _effective_stmts(user, iam):
    stmts = []

    for p in user.get("UserPolicyList", []):
        stmts.extend(p.get("PolicyDocument", {}).get("Statement", []))

    pdocs = iam.get("policy_docs", {})
    for p in user.get("AttachedManagedPolicies", []):
        for vid, doc in pdocs.get(p.get("PolicyArn", ""), {}).items():
            stmts.extend(doc.get("Statement", []))

    # group memberships
    for gname in user.get("GroupList", []):
        for grp in iam.get("groups", []):
            if grp.get("GroupName") != gname:
                continue
            for p in grp.get("GroupPolicyList", []):
                stmts.extend(p.get("PolicyDocument", {}).get("Statement", []))
            for p in grp.get("AttachedManagedPolicies", []):
                for vid, doc in pdocs.get(p.get("PolicyArn", ""), {}).items():
                    stmts.extend(doc.get("Statement", []))

    return [s for s in stmts if s.get("Effect") == "Allow"]


def _role_stmts(role, iam):
    stmts = []
    for p in role.get("RolePolicyList", []):
        stmts.extend(p.get("PolicyDocument", {}).get("Statement", []))

    pdocs = iam.get("policy_docs", {})
    for p in role.get("AttachedManagedPolicies", []):
        for vid, doc in pdocs.get(p.get("PolicyArn", ""), {}).items():
            stmts.extend(doc.get("Statement", []))

    return [s for s in stmts if s.get("Effect") == "Allow"]


def _grants(stmts, action, resource="*"):
    for s in stmts:
        acts = s.get("Action", [])
        if isinstance(acts, str):
            acts = [acts]
        res = s.get("Resource", [])
        if isinstance(res, str):
            res = [res]

        for a in acts:
            if not fnmatch.fnmatch(action.lower(), a.lower()):
                continue
            for r in res:
                if resource == "*" or r == "*" or fnmatch.fnmatch(resource, r):
                    return True
    return False
