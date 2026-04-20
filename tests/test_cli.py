import json
from pathlib import Path
from unittest.mock import patch

import networkx as nx
import pytest

from domino.cli import _pick_start, main
from domino.graph import build_graph
from domino.recon import load_snapshot

SNAP = Path(__file__).resolve().parent.parent / "domino" / "snapshot.json"


@pytest.fixture
def snap():
    return load_snapshot(str(SNAP))


@pytest.fixture
def g(snap):
    return build_graph(snap)


# _pick_start


def test_pick_start_prefers_user(g):
    start = _pick_start(g)
    assert start is not None
    assert g.nodes[start].get("kind") == "user"


def test_pick_start_no_users():
    g = nx.MultiDiGraph()
    g.add_node("arn:aws:iam::123:role/svc", kind="role")
    g.add_node("arn:aws:iam::123:role/other", kind="role")
    got = _pick_start(g)
    assert got is not None
    assert g.nodes[got].get("kind") == "role"


def test_pick_start_empty_graph():
    g = nx.MultiDiGraph()
    assert _pick_start(g) is None


# main() integration tests


def test_demo_mode(capsys):
    with patch("sys.argv", ["domino", "--demo"]):
        main()
    out = capsys.readouterr().out
    assert "domino found" in out or "no exploit chains" in out


def test_demo_verbose(capsys):
    with patch("sys.argv", ["domino", "--demo", "-v"]):
        main()
    out = capsys.readouterr().out
    assert "domino found" in out


def test_snapshot_mode(capsys):
    with patch("sys.argv", ["domino", "--snapshot", str(SNAP)]):
        main()
    out = capsys.readouterr().out
    assert "domino found" in out or "no exploit chains" in out


def test_snapshot_with_start_principal(capsys):
    with patch(
        "sys.argv",
        [
            "domino",
            "--snapshot",
            str(SNAP),
            "-s",
            "arn:aws:iam::123456789012:user/dev-user",
        ],
    ):
        main()
    out = capsys.readouterr().out
    assert "domino found" in out


def test_json_export(capsys, tmp_path):
    out_file = tmp_path / "chains.json"
    with patch("sys.argv", ["domino", "--demo", "--json-out", str(out_file)]):
        main()
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert isinstance(data, list)


def test_no_args_exits(capsys):
    with patch("sys.argv", ["domino"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1


def test_unknown_principal_exits(capsys):
    with patch(
        "sys.argv",
        [
            "domino",
            "--demo",
            "-s",
            "arn:aws:iam::999:user/ghost",
        ],
    ):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "principal_not_found" in err


def test_max_depth_flag(capsys):
    with patch("sys.argv", ["domino", "--demo", "--max-depth", "2"]):
        main()
    # should still run, just fewer chains
    out = capsys.readouterr().out
    assert "domino found" in out or "no exploit chains" in out
