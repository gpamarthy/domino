import argparse
import sys
from pathlib import Path

from .core.database import DominoDB
from .core.logger import setup_logger
from .graph import build_graph
from .output import export_json, render_chains
from .recon import collect_live, load_snapshot
from .tactics import find_chains


def _pick_start(g):
    for nid, attrs in g.nodes(data=True):
        if attrs.get("kind") == "user":
            return nid
    return next(iter(g.nodes)) if g.nodes else None


def main():
    p = argparse.ArgumentParser(
        prog="domino",
        description="AWS exploit chain prover - finds cross-service privilege escalation paths",
        epilog="""examples:
  domino --demo                         run against bundled test snapshot
  domino --profile prod -s arn:aws:iam::123456789:user/dev
  domino --snapshot ./recon.json --json-out chains.json -v""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src = p.add_mutually_exclusive_group()
    src.add_argument("--profile", help="AWS CLI profile for live collection")
    src.add_argument("--snapshot", help="path to JSON snapshot file")

    p.add_argument("-s", "--start-principal", help="starting ARN (default: first user)")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--json-out", help="export chains to JSON file")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--demo", action="store_true", help="use bundled demo snapshot")
    p.add_argument("--db-path", help="path to SQLite database")

    args = p.parse_args()

    log = setup_logger(verbose=args.verbose)
    db = DominoDB(args.db_path)

    # figure out data source
    snapshot_id = None
    if args.demo:
        snap = Path(__file__).parent / "snapshot.json"
        if not snap.exists():
            log.error("demo_snapshot_not_found", path=str(snap))
            sys.exit(1)
        data = load_snapshot(str(snap))
    elif args.snapshot:
        data = load_snapshot(args.snapshot)
    elif args.profile:
        log.info("collecting_live_data", profile=args.profile, region=args.region)
        data = collect_live(args.profile, args.region)
        snapshot_id = db.save_snapshot(args.profile, args.region, data)
    else:
        p.print_help()
        sys.exit(1)

    log.info(
        "building_graph",
        nodes=len(data.get("iam", {}).get("users", [])) + len(data.get("iam", {}).get("roles", [])),
    )
    g = build_graph(data)

    start = args.start_principal
    if not start:
        start = _pick_start(g)
        if not start:
            log.error("empty_graph")
            sys.exit(1)
        if not args.demo:
            log.info("auto_selected_principal", principal=start)

    if start not in g:
        log.error("principal_not_found", principal=start, node_count=len(g.nodes))
        sys.exit(1)

    log.info("finding_exploit_chains", start=start, max_depth=args.max_depth)
    chains = find_chains(g, start, max_depth=args.max_depth)

    if snapshot_id:
        db.save_scan(snapshot_id, start, chains)

    render_chains(chains, verbose=args.verbose)

    if args.json_out:
        export_json(chains, args.json_out)
        log.info("exported_results", path=args.json_out)


if __name__ == "__main__":
    main()
