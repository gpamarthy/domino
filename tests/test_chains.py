import json
from pathlib import Path

import networkx as nx
import pytest

from domino.graph import (
    ASSUME,
    CREATE_ATTACH,
    IMDS_STEAL,
    PASSROLE,
    S3_TRIGGER,
    USES_ROLE,
    build_graph,
)
from domino.output import _short_arn, export_json
from domino.recon import load_snapshot
from domino.tactics import find_chains

SNAP = Path(__file__).resolve().parent.parent / "domino" / "snapshot.json"

DEV = "arn:aws:iam::123456789012:user/dev-user"
ADMIN_ROLE = "arn:aws:iam::123456789012:role/admin-role"
ADMIN_LAMBDA = "arn:aws:iam::123456789012:role/admin-lambda-role"
STAGING = "arn:aws:iam::123456789012:role/staging-role"
DEPLOY = "arn:aws:iam::123456789012:role/deploy-role"
WEB_ROLE = "arn:aws:iam::123456789012:role/web-role"
EC2_WEB = "ec2:i-webserver01"
BUCKET = "s3:data-inbox"


@pytest.fixture(scope="module")
def snap():
    return load_snapshot(str(SNAP))


@pytest.fixture(scope="module")
def g(snap):
    return build_graph(snap)


# graph construction


def test_node_count(g):
    # 1 user + 6 roles + 1 s3 + 1 ec2 + 1 lambda + 1 "anyone" from bucket policy
    assert len(g.nodes) >= 11


def test_node_kinds(g):
    kinds = {g.nodes[n].get("kind") for n in g.nodes}
    assert {"user", "role", "s3", "ec2", "lambda", "external"} <= kinds


def test_admin_role_flagged(g):
    assert g.nodes[ADMIN_ROLE].get("admin") is True
    assert g.nodes[ADMIN_LAMBDA].get("admin") is True


def test_non_admin_role_not_flagged(g):
    assert not g.nodes[STAGING].get("admin")
    assert not g.nodes[DEPLOY].get("admin")


def test_public_bucket(g):
    assert g.nodes[BUCKET].get("public") is True


def test_edge_types_present(g):
    edge_kinds = {d.get("kind") for _, _, d in g.edges(data=True)}
    assert ASSUME in edge_kinds
    assert PASSROLE in edge_kinds
    assert CREATE_ATTACH in edge_kinds
    assert S3_TRIGGER in edge_kinds
    assert USES_ROLE in edge_kinds
    assert IMDS_STEAL in edge_kinds


def test_ec2_uses_role_edge(g):
    edges = g.get_edge_data(EC2_WEB, WEB_ROLE)
    assert edges is not None
    kinds = {e.get("kind") for e in edges.values()}
    assert USES_ROLE in kinds


def test_ec2_imds_edge(g):
    edges = g.get_edge_data(EC2_WEB, WEB_ROLE)
    kinds = {e.get("kind") for e in edges.values()}
    assert IMDS_STEAL in kinds


def test_s3_trigger_edge(g):
    fn_arn = "arn:aws:lambda:us-east-1:123456789012:function:data-processor"
    edges = g.get_edge_data(BUCKET, fn_arn)
    assert edges is not None
    kinds = {e.get("kind") for e in edges.values()}
    assert S3_TRIGGER in kinds


# chains


@pytest.fixture(scope="module")
def dev_chains(g):
    return find_chains(g, DEV)


@pytest.fixture(scope="module")
def ec2_chains(g):
    return find_chains(g, EC2_WEB)


@pytest.fixture(scope="module")
def anon_chains(g):
    return find_chains(g, "anyone")


def test_dev_finds_passrole_lambda(dev_chains):
    hits = [c for c in dev_chains if c["tactic"] == "PassRole+Lambda Escalation"]
    assert len(hits) >= 1
    assert any(c["score"] == 10.0 for c in hits)


def test_dev_finds_role_assumption(dev_chains):
    hits = [c for c in dev_chains if c["tactic"] == "Role Assumption Chain"]
    assert len(hits) >= 1
    # should go through staging-role
    assert any(STAGING in c["path"] for c in hits)


def test_dev_chain_count(dev_chains):
    assert len(dev_chains) >= 2


def test_ec2_finds_chain_to_admin(ec2_chains):
    # ec2 -> web-role -> deploy-role -> admin-role
    hits = [c for c in ec2_chains if ADMIN_ROLE in c["path"]]
    assert len(hits) >= 1
    for c in hits:
        assert WEB_ROLE in c["path"] or DEPLOY in c["path"]


def test_ec2_chain_count(ec2_chains):
    assert len(ec2_chains) >= 1


def test_anon_confused_deputy(anon_chains):
    hits = [c for c in anon_chains if c["tactic"] == "Confused Deputy via S3"]
    assert len(hits) >= 1


def test_anon_chain_count(anon_chains):
    assert len(anon_chains) >= 1


# scoring


def test_passrole_lambda_max_score(dev_chains):
    hits = [c for c in dev_chains if c["tactic"] == "PassRole+Lambda Escalation"]
    assert hits[0]["score"] == 10.0


def test_longer_chain_scores_lower(dev_chains):
    by_len = sorted(dev_chains, key=lambda c: len(c["path"]))
    if len(by_len) >= 2:
        short, long = by_len[0], by_len[-1]
        if short["tactic"] == long["tactic"]:
            assert short["score"] >= long["score"]


def test_admin_target_scores_higher(g):
    # compare same-tactic chains from ec2 -- admin targets get bonus
    chains = find_chains(g, EC2_WEB)
    admin_chains = [c for c in chains if g.nodes.get(c["target"], {}).get("admin")]
    if admin_chains:
        assert all(c["score"] >= 1.0 for c in admin_chains)


# edge cases


def test_empty_graph_no_chains():
    empty = nx.MultiDiGraph()
    assert find_chains(empty, "nobody") == []


def test_missing_principal_raises(g):
    with pytest.raises(nx.NodeNotFound):
        find_chains(g, "arn:aws:iam::999999999999:user/ghost")


def test_single_node_no_chains():
    solo = nx.MultiDiGraph()
    solo.add_node("lonely", kind="user")
    assert find_chains(solo, "lonely") == []


def test_graph_with_no_targets():
    g = nx.MultiDiGraph()
    g.add_node("a", kind="user")
    g.add_node("b", kind="role", admin=False)
    g.add_edge("a", "b", kind=ASSUME, weight=1)
    assert find_chains(g, "a") == []


# output helpers


def test_short_arn_iam():
    assert _short_arn("arn:aws:iam::123456789012:user/dev") == "user/dev"
    assert _short_arn("arn:aws:iam::123456789012:role/admin") == "role/admin"


def test_short_arn_lambda():
    arn = "arn:aws:lambda:us-east-1:123456789012:function:proc"
    assert _short_arn(arn) == "lambda:proc"


def test_short_arn_s3():
    assert _short_arn("s3:mybucket") == "s3:mybucket"


def test_short_arn_none():
    assert _short_arn(None) == "None"
    assert _short_arn("") == ""


def test_export_json_valid(dev_chains, tmp_path):
    out = tmp_path / "chains.json"
    export_json(dev_chains, str(out))
    loaded = json.loads(out.read_text())
    assert isinstance(loaded, list)
    assert len(loaded) == len(dev_chains)
    for c in loaded:
        assert "score" in c
        assert "tactic" in c
        assert "path" in c


# real-world scenario tests

SNAPS = Path(__file__).resolve().parent / "snapshots"


@pytest.fixture
def cloudgoat_g():
    return build_graph(load_snapshot(str(SNAPS / "cloudgoat_lambda.json")))


@pytest.fixture
def cap1_g():
    return build_graph(load_snapshot(str(SNAPS / "capital_one.json")))


@pytest.fixture
def iamvuln_g():
    return build_graph(load_snapshot(str(SNAPS / "iam_vulns.json")))


def test_cloudgoat_passrole_lambda(cloudgoat_g):
    chains = find_chains(cloudgoat_g, "arn:aws:iam::112233445566:user/chris")
    assert any(c["tactic"] == "PassRole+Lambda Escalation" for c in chains)


def test_capital_one_imds_chain(cap1_g):
    chains = find_chains(cap1_g, "ec2:i-webapp01")
    assert len(chains) >= 1
    assert any("IMDS" in c["tactic"] for c in chains)


def test_iam_self_escalation(iamvuln_g):
    chains = find_chains(iamvuln_g, "arn:aws:iam::554433221100:user/privesc-attach-user")
    assert len(chains) >= 1
    assert chains[0]["tactic"] == "IAM Policy Self-Escalation"
    assert chains[0]["score"] == 10.0


def test_lambda_hijack(iamvuln_g):
    chains = find_chains(iamvuln_g, "arn:aws:iam::554433221100:user/privesc-lambda-update-user")
    assert any(c["tactic"] == "Lambda Code Hijack" for c in chains)


def test_assume_role_chain_3hop(iamvuln_g):
    chains = find_chains(iamvuln_g, "arn:aws:iam::554433221100:user/privesc-assume-chain-user")
    assert any(c["tactic"] == "Role Assumption Chain" for c in chains)


# -- GitHub scenario: CloudGoat codebuild_secrets pattern --
# ref: RhinoSecurityLabs/cloudgoat scenarios/aws/codebuild_secrets
# developer -> AssumeRole -> ci-runner -> PassRole+CodeBuild -> deploy-admin


@pytest.fixture
def codebuild_g():
    return build_graph(load_snapshot(str(SNAPS / "codebuild_chain.json")))


def test_codebuild_chain_found(codebuild_g):
    chains = find_chains(codebuild_g, "arn:aws:iam::334455667788:user/developer")
    assert len(chains) >= 1


def test_codebuild_tactic_detected(codebuild_g):
    chains = find_chains(codebuild_g, "arn:aws:iam::334455667788:user/developer")
    hits = [c for c in chains if c["tactic"] == "PassRole+CodeBuild Escalation"]
    assert len(hits) >= 1
    # chain should transit through ci-runner-role
    assert any("arn:aws:iam::334455667788:role/ci-runner-role" in c["path"] for c in hits)


def test_codebuild_target_is_admin(codebuild_g):
    chains = find_chains(codebuild_g, "arn:aws:iam::334455667788:user/developer")
    hits = [c for c in chains if c["tactic"] == "PassRole+CodeBuild Escalation"]
    assert hits[0]["target"] == "arn:aws:iam::334455667788:role/deploy-admin-role"
    assert codebuild_g.nodes[hits[0]["target"]].get("admin") is True


def test_codebuild_chain_is_2hop(codebuild_g):
    chains = find_chains(codebuild_g, "arn:aws:iam::334455667788:user/developer")
    hits = [c for c in chains if c["tactic"] == "PassRole+CodeBuild Escalation"]
    # developer -> ci-runner -> deploy-admin = 3 nodes, 2 edges
    assert len(hits[0]["path"]) == 3
    assert len(hits[0]["edges"]) == 2


# -- GitHub scenario: EC2 IMDS + Lambda hijack compound chain --
# ref: compound chain combining IMDSv1 theft + lambda:UpdateFunctionCode
# ec2:i-dev01 -> IMDS/uses_role -> app-role -> lambda_hijack -> fn -> uses_role -> admin


@pytest.fixture
def imds_hijack_g():
    return build_graph(load_snapshot(str(SNAPS / "imds_lambda_hijack.json")))


def test_imds_hijack_chain_found(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    assert len(chains) >= 1


def test_imds_hijack_reaches_admin(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    admin_chains = [
        c for c in chains if c["target"] == "arn:aws:iam::445566778899:role/admin-exec-role"
    ]
    assert len(admin_chains) >= 1
    assert imds_hijack_g.nodes[admin_chains[0]["target"]].get("admin") is True


def test_imds_hijack_detects_lambda_hijack_tactic(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    assert any(c["tactic"] == "Lambda Code Hijack" for c in chains)


def test_imds_hijack_detects_imds_tactic(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    assert any(c["tactic"] == "EC2 IMDS Credential Theft" for c in chains)


def test_imds_hijack_is_3hop(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    # ec2 -> app-role -> fn -> admin-exec-role = 4 nodes, 3 edges
    for c in chains:
        assert len(c["path"]) == 4
        assert len(c["edges"]) == 3


def test_imds_hijack_edge_types(imds_hijack_g):
    chains = find_chains(imds_hijack_g, "ec2:i-dev01")
    all_kinds = set()
    for c in chains:
        for e in c["edges"]:
            all_kinds.add(e["kind"])
    # must see lambda_hijack, uses_role, and imds_creds across the chains
    assert "lambda_hijack" in all_kinds
    assert "uses_role" in all_kinds
    assert "imds_creds" in all_kinds
