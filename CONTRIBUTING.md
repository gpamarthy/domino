# Contributing

Thanks for considering a contribution.

## Useful contributions

1. **New attack edges** in `domino/graph.py`. A new edge is a known IAM-to-resource transition (e.g. `iam:PassRole` to `lambda:CreateFunction`, `sts:AssumeRole` across accounts, `kms:Decrypt` plus `s3:GetObject`).
2. **New recon modules** for AWS services not yet covered (ECR, Secrets Manager, CodeBuild, etc.) under `domino/recon.py`.
3. **Snapshot fixtures** in `tests/snapshots/` that exercise new chain shapes. Sanitize account IDs and resource names.
4. **Documentation** of how a real-world AWS escalation chain maps onto the graph model.

## Dev setup

```sh
git clone https://github.com/gpamarthy/domino
cd domino
pip install -e .[dev]
make ci          # lint + typecheck + test + security
make dev         # incremental: lint + test
```

## Code style

- Python 3.10+. `ruff check .` and `mypy domino/` must pass.
- Four-space indent. Type-annotate public functions.
- No emojis. Plain prose in commits, comments, and PR descriptions.
- Conventional commits: `feat(recon):`, `fix(graph):`, `chore:`, `docs:`, `ci:`.

## Adding an edge

An edge lives in `domino/graph.py:_build_edges()` and:

1. Has a unique edge label.
2. Has a test in `tests/test_graph.py` exercising a snapshot where the edge fires.
3. Adds an entry to `CHANGELOG.md` under `[Unreleased]`.
