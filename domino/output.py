import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()

# edge kind -> human-readable label for chain display
EDGE_LABELS = {
    "assume_role": "AssumeRole",
    "pass_role": "PassRole",  # nosec B105 - display label, not a password
    "uses_role": "ExecAs",
    "s3_trigger": "S3-Lambda",
    "imds_creds": "IMDS-Steal",
    "create": "Create+PassRole",
    "s3_access": "S3Access",
    "iam_escalate": "IAM-SelfEsc",
    "lambda_hijack": "Lambda-Hijack",
}


def render_chains(chains, verbose=False):
    if not chains:
        console.print("[yellow]no exploit chains found from this principal[/yellow]")
        return

    n = len(chains)
    console.print(
        Panel(
            f"[bold]domino found {n} exploit chain{'s' if n != 1 else ''}[/bold]",
            style="bright_blue",
        )
    )

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("#", width=3, justify="right")
    tbl.add_column("Score", width=6, justify="center")
    tbl.add_column("Tactic", min_width=20)
    tbl.add_column("Chain", min_width=30)
    tbl.add_column("Target", min_width=15)

    for i, c in enumerate(chains, 1):
        score = c["score"]
        if score >= 8:
            sc_str = f"[red]{score:.1f}[/red]"
        elif score >= 5:
            sc_str = f"[yellow]{score:.1f}[/yellow]"
        else:
            sc_str = f"[green]{score:.1f}[/green]"

        chain_str = _fmt_chain(c)
        tbl.add_row(str(i), sc_str, c["tactic"], chain_str, _short_arn(c["target"]))

    console.print(tbl)

    if verbose:
        console.print()
        for i, c in enumerate(chains, 1):
            _render_tree(i, c)


def export_json(chains, path):
    # strip lambda match_fn refs that aren't serializable
    clean = []
    for c in chains:
        out = dict(c)
        clean.append(out)

    with open(path, "w") as f:
        json.dump(clean, f, indent=2, default=str)
    console.print(f"[dim]wrote {len(clean)} chains to {path}[/dim]")


def _short_arn(arn):
    if not arn or not isinstance(arn, str):
        return str(arn)

    if arn.startswith("s3:"):
        return arn

    if ":function:" in arn:
        return "lambda:" + arn.split(":")[-1]

    if "/" in arn:
        return arn.split(":")[-1]

    return arn


def _fmt_chain(c):
    parts = []
    path = c["path"]
    edges = c["edges"]

    parts.append(_short_arn(path[0]))
    for e in edges:
        label = EDGE_LABELS.get(e["kind"], e["kind"])
        parts.append(f"->[{label}]->")
        parts.append(_short_arn(e["dst"]))

    return " ".join(parts)


def _render_tree(idx, c):
    root = Tree(f"[bold]Chain #{idx}[/bold] - {c['tactic']} (score: {c['score']:.1f})")

    for e in c["edges"]:
        label = EDGE_LABELS.get(e["kind"], e["kind"])
        desc = e.get("desc", "")
        node_text = f"{_short_arn(e['src'])} -[{label}]-> {_short_arn(e['dst'])}"
        if desc:
            node_text += f"  [dim]({desc})[/dim]"

        branch = root.add(node_text)
        w = e.get("weight", 0)
        if w >= 3:
            branch.add("[red]high difficulty[/red]")
        elif w >= 2:
            branch.add("[yellow]moderate[/yellow]")

    target = c["target"]
    kind = c.get("target_kind", "")
    t = Text(f"--- target: {_short_arn(target)} ({kind})", style="bold red")
    root.add(t)

    console.print(root)
    console.print()
