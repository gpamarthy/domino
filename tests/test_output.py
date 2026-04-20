from domino.output import EDGE_LABELS, _fmt_chain, _render_tree, render_chains


def _make_chain(tactic="Role Assumption Chain", score=7.5, hops=2, weight=2):
    edges = []
    path = ["arn:aws:iam::123:user/attacker"]
    for i in range(hops):
        dst = f"arn:aws:iam::123:role/hop{i}"
        edges.append(
            {
                "src": path[-1],
                "dst": dst,
                "kind": "assume_role",
                "weight": weight,
                "desc": f"assume step {i}",
            }
        )
        path.append(dst)

    return {
        "path": path,
        "edges": edges,
        "tactic": tactic,
        "score": score,
        "target": path[-1],
        "target_kind": "role",
    }


# render_chains


def test_render_empty_chains(capsys):
    render_chains([])
    out = capsys.readouterr().out
    assert "no exploit chains" in out


def test_render_single_chain(capsys):
    chains = [_make_chain(score=9.5)]
    render_chains(chains)
    out = capsys.readouterr().out
    assert "1 exploit chain" in out


def test_render_multiple_chains(capsys):
    chains = [
        _make_chain(score=9.0, tactic="PassRole+Lambda Escalation"),
        _make_chain(score=5.5, tactic="Role Assumption Chain"),
        _make_chain(score=3.0, tactic="EC2 IMDS Credential Theft"),
    ]
    render_chains(chains)
    out = capsys.readouterr().out
    assert "3 exploit chains" in out


def test_render_verbose(capsys):
    chains = [_make_chain(score=8.0)]
    render_chains(chains, verbose=True)
    out = capsys.readouterr().out
    assert "Chain #1" in out


def test_render_score_colors(capsys):
    # high, mid, low scores exercise all branches
    chains = [
        _make_chain(score=9.0),
        _make_chain(score=5.5, tactic="Mid"),
        _make_chain(score=2.0, tactic="Low"),
    ]
    render_chains(chains)
    # just verify it doesn't crash - color codes are in rich markup


# _fmt_chain


def test_fmt_chain_basic():
    c = _make_chain(hops=1)
    result = _fmt_chain(c)
    assert "AssumeRole" in result
    assert "->" in result


def test_fmt_chain_multi_hop():
    c = _make_chain(hops=3)
    result = _fmt_chain(c)
    assert result.count("->") >= 3


def test_fmt_chain_unknown_edge_kind():
    c = _make_chain(hops=1)
    c["edges"][0]["kind"] = "weird_edge"
    result = _fmt_chain(c)
    assert "weird_edge" in result


# _render_tree


def test_render_tree_basic(capsys):
    c = _make_chain(score=7.0)
    _render_tree(1, c)
    out = capsys.readouterr().out
    assert "Chain #1" in out
    assert "target:" in out


def test_render_tree_high_weight(capsys):
    c = _make_chain(weight=3)
    _render_tree(1, c)
    out = capsys.readouterr().out
    assert "high difficulty" in out


def test_render_tree_moderate_weight(capsys):
    c = _make_chain(weight=2)
    _render_tree(1, c)
    out = capsys.readouterr().out
    assert "moderate" in out


def test_render_tree_no_desc(capsys):
    c = _make_chain()
    for e in c["edges"]:
        e["desc"] = ""
    _render_tree(1, c)
    out = capsys.readouterr().out
    assert "Chain #1" in out


# edge labels coverage


def test_edge_labels_all_known():
    expected_kinds = [
        "assume_role",
        "pass_role",
        "uses_role",
        "s3_trigger",
        "imds_creds",
        "create",
        "s3_access",
        "iam_escalate",
        "lambda_hijack",
    ]
    for kind in expected_kinds:
        assert kind in EDGE_LABELS
