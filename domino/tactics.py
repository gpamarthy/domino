from itertools import product
from pathlib import Path

import networkx as nx
import yaml

from .graph import IAM_ESCALATE


def load_tactics():
    """Load tactics from rules/tactics.yaml"""
    # Try local rules directory first, then fallback to package data
    paths = [
        Path(__file__).parent.parent / "rules" / "tactics.yaml",
        Path("/home/kali/gemini/projects/domino/rules/tactics.yaml"),
    ]

    for p in paths:
        if p.exists():
            with open(p, "r") as f:
                raw = yaml.safe_load(f)
                return [_parse_tactic(t) for t in raw]
    return []


def _parse_tactic(t):
    name = t["name"]
    multiplier = t["multiplier"]
    match_cfg = t["match"]

    def match_fn(edges):
        if "any" in match_cfg:
            cfg = match_cfg["any"]
            kind = cfg.get("kind")
            contains = cfg.get("desc_contains")
            return any(
                e["kind"] == kind and (not contains or contains in e.get("desc", "")) for e in edges
            )
        if "subsequence" in match_cfg:
            needle = match_cfg["subsequence"]
            haystack = [e["kind"] for e in edges]
            return _subseq_match(haystack, needle)
        if "min_count" in match_cfg:
            cfg = match_cfg["min_count"]
            kind = cfg["kind"]
            count = cfg["count"]
            return sum(1 for e in edges if e["kind"] == kind) >= count
        if "exact" in match_cfg:
            cfg = match_cfg["exact"]
            kind = cfg["kind"]
            return len(edges) == 1 and edges[0]["kind"] == kind
        return False

    return {
        "name": name,
        "multiplier": multiplier,
        "match_fn": match_fn,
    }


TACTICS = load_tactics()


def find_chains(g, start_arn, max_depth=6):
    targets = _find_targets(g)
    if not targets:
        return []

    chains = []

    # special case: check if the start principal can self-escalate
    self_edges = g.get_edge_data(start_arn, start_arn)
    if self_edges:
        for key, edata in self_edges.items():
            if edata.get("kind") == IAM_ESCALATE:
                edge = {
                    "src": start_arn,
                    "dst": start_arn,
                    "kind": IAM_ESCALATE,
                    "weight": edata.get("weight", 1),
                    "desc": edata.get("desc", ""),
                }
                chains.append(
                    {
                        "path": [start_arn],
                        "edges": [edge],
                        "tactic": "IAM Policy Self-Escalation",
                        "score": 10.0,
                        "target": start_arn,
                        "target_kind": g.nodes.get(start_arn, {}).get("kind", "unknown"),
                    }
                )
                break

    target_set = set(targets)

    for t in targets:
        if t == start_arn:
            continue

        admin_set = {n for n in target_set if g.nodes.get(n, {}).get("admin")}
        keep = {n for n in g.nodes if n not in admin_set or n in (start_arn, t)}
        sub = g.subgraph(keep)

        try:
            paths = nx.all_simple_paths(sub, start_arn, t, cutoff=max_depth)
        except (nx.NodeNotFound, nx.NetworkXError):
            continue

        for path in paths:
            target_node = g.nodes.get(t, {})

            for edges in _path_edge_combos(g, path):
                if not edges:
                    continue
                tactic = _match_tactic(edges)
                score = _score_chain(path, edges, tactic, g)

                chains.append(
                    {
                        "path": list(path),
                        "edges": edges,
                        "tactic": tactic["name"] if tactic else "Unknown",
                        "score": round(score, 2),
                        "target": t,
                        "target_kind": target_node.get("kind", "unknown"),
                    }
                )

    chains = _dedup(chains)
    chains.sort(key=lambda c: c["score"], reverse=True)
    return chains


def _find_targets(g):
    out = []
    for nid, attrs in g.nodes(data=True):
        if attrs.get("admin"):
            out.append(nid)
        elif attrs.get("kind") == "s3" and attrs.get("public"):
            out.append(nid)
    for u, v, d in g.edges(data=True):
        if u == v and d.get("kind") == IAM_ESCALATE and u not in out:
            out.append(u)
    return out


def _path_edge_combos(g, path):
    step_opts = []
    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        edata = g.get_edge_data(src, dst) or {}
        seen = {}
        for key, attrs in edata.items():
            k = attrs.get("kind", "")
            if k not in seen:
                seen[k] = {
                    "src": src,
                    "dst": dst,
                    "kind": k,
                    "weight": attrs.get("weight", 1),
                    "desc": attrs.get("desc", ""),
                }
        if not seen:
            return
        step_opts.append(list(seen.values()))
    for combo in product(*step_opts):
        yield list(combo)


def _match_tactic(edges):
    if not edges:
        return None
    for t in TACTICS:
        if t["match_fn"](edges):
            return t
    return None


def _subseq_match(haystack, needle):
    it = iter(haystack)
    return all(n in it for n in needle)


def _score_chain(path, edges, tactic, g):
    if not tactic:
        return min(3.0, 10.0 / max(len(path), 1))
    hops = len(path) - 1
    total_weight = sum(e["weight"] for e in edges)
    target = path[-1]
    target_bonus = 2.0 if g.nodes.get(target, {}).get("admin") else 1.0
    multiplier = tactic["multiplier"]
    denom = hops * 0.5 + total_weight * 0.3
    if denom <= 0:
        denom = 0.1
    raw = (multiplier * target_bonus) / denom
    return min(raw, 10.0)


def _dedup(chains):
    seen = {}
    for c in chains:
        key = (c["tactic"], c["target"])
        if key not in seen or c["score"] > seen[key]["score"]:
            seen[key] = c
    covered = {c["target"] for c in seen.values() if c["tactic"] != "Unknown"}
    return [c for c in seen.values() if c["tactic"] != "Unknown" or c["target"] not in covered]
