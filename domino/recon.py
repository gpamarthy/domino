import json

import boto3
import structlog
from botocore.exceptions import ClientError

logger = structlog.get_logger()


def load_snapshot(path):
    with open(path) as f:
        return json.load(f)


def save_snapshot(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def collect_live(profile, region="us-east-1"):
    sess = boto3.Session(profile_name=profile, region_name=region)

    acct = _get_account_id(sess)
    logger.info("collecting_aws_data", account_id=acct, region=region)

    data = {
        "account_id": acct,
        "iam": _collect_iam(sess),
        "s3": _collect_s3(sess),
        "ec2": _collect_ec2(sess, region),
        "lambda": _collect_lambda(sess, region),
    }

    logger.info(
        "collection_complete",
        users=len(data["iam"]["users"]),
        roles=len(data["iam"]["roles"]),
        buckets=len(data["s3"]["buckets"]),
        instances=len(data["ec2"]["instances"]),
        functions=len(data["lambda"]["functions"]),
    )

    return data


def _get_account_id(sess):
    return sess.client("sts").get_caller_identity()["Account"]


def _collect_iam(sess):
    iam = sess.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")

    users, roles, groups = [], [], []
    policy_docs = {}

    for page in paginator.paginate():
        users.extend(page.get("UserDetailList", []))
        roles.extend(page.get("RoleDetailList", []))
        groups.extend(page.get("GroupDetailList", []))

        for p in page.get("Policies", []):
            arn = p["Arn"]
            policy_docs[arn] = {}
            for ver in p.get("PolicyVersionList", []):
                policy_docs[arn][ver["VersionId"]] = ver["Document"]

    return {
        "users": users,
        "roles": roles,
        "groups": groups,
        "policy_docs": policy_docs,
    }


def _collect_s3(sess):
    s3 = sess.client("s3")
    buckets = []

    try:
        raw = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.error("s3_list_failed", error=str(e))
        return {"buckets": []}

    for b in raw:
        name = b["Name"]
        bkt = {"Name": name, "Policy": None, "PublicAccessBlock": None, "ACL": None}

        try:
            raw_pol = s3.get_bucket_policy(Bucket=name)["Policy"]
            bkt["Policy"] = json.loads(raw_pol) if isinstance(raw_pol, str) else raw_pol
        except ClientError:
            pass

        try:
            bkt["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError:
            pass

        try:
            bkt["ACL"] = s3.get_bucket_acl(Bucket=name)
        except ClientError:
            pass

        buckets.append(bkt)

    return {"buckets": buckets}


def _collect_ec2(sess, region):
    ec2 = sess.client("ec2", region_name=region)
    instances = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                instances.extend(res["Instances"])
    except ClientError as e:
        logger.error("ec2_describe_failed", error=str(e))

    return {"instances": instances}


def _collect_lambda(sess, region):
    lam = sess.client("lambda", region_name=region)
    funcs = []

    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                try:
                    esm = lam.list_event_source_mappings(FunctionName=fn["FunctionName"])
                    fn["EventSourceMappings"] = esm.get("EventSourceMappings", [])
                except ClientError:
                    fn["EventSourceMappings"] = []
                funcs.append(fn)
    except ClientError as e:
        logger.error("lambda_list_failed", error=str(e))

    return {"functions": funcs}
