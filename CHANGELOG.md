# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-13

First public release. AWS IAM privilege-escalation chain prover.

### Added
- Live-account recon via `recon.py`: enumerates IAM entities, S3, EC2, Lambda, KMS, STS reachability
- Snapshot persistence in `DominoDB` (SQLite) for offline analysis across runs
- Attack-graph builder using `networkx` with per-action edge labels
- Chain-finder (`find_chains`) that surfaces shortest paths from any principal to any privilege of interest
- `--demo` flag that ships with a bundled stress-test snapshot (no AWS creds required)
- JSON output mode for downstream tooling (`--json-out`)
- 67 unit and snapshot tests across Python 3.10, 3.11, 3.12
- CI: ruff lint, mypy typecheck, pytest, pip-audit security
- Pre-commit framework wiring for local lint enforcement
