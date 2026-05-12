# Domino

**AWS Exploit Chain Prover**

Domino is a specialized security tool for AWS environments that identifies multi-step privilege escalation paths. While traditional scanners report individual misconfigurations, Domino builds a directed graph of IAM principals and resources to uncover how those vulnerabilities can be chained together to achieve full account compromise.

---

## 🛡️ Security Disclaimer

**FOR EDUCATIONAL AND ETHICAL TESTING PURPOSES ONLY.**
The use of Domino for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## ✨ Features

- **Graph-Based Analysis**: Models IAM relationships using `networkx` to find non-obvious attack paths.
- **YAML Tactics Engine**: Customizable attack patterns defined in `rules/tactics.yaml`.
- **Cross-Service Escalation**: Identifies chains involving IAM, S3, Lambda, EC2, Glue, and more.
- **Heuristic Scoring**: Ranks exploit chains by severity (0-10) based on tactic type and exploitation difficulty.
- **State Management**: Persistent storage of IAM snapshots and scan results in SQLite.
- **Structured Logging**: JSON output for SIEM integration and pretty-printing for terminal use.
- **Live & Offline Modes**: Analyze active AWS environments or work from local JSON snapshots.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/gpamarthy/domino.git
cd domino

# Install dependencies
pip install .

# For development (includes testing tools)
pip install -e '.[dev]'
```

### Basic Usage

**Run the Demo** (uses bundled snapshot, no AWS credentials required):
```bash
domino --demo
```

**Live Analysis** (requires AWS CLI profile):
```bash
domino --profile prod --start-principal arn:aws:iam::123456789012:user/analyst
```

**Offline Analysis** (using a pre-collected snapshot):
```bash
domino --snapshot ./recon.json --json-out results.json -v
```

---

## 🏗️ Architectural Overview

Domino operates in three primary phases:

1.  **Reconnaissance**: Collects IAM policies, S3 metadata, EC2 configurations, and Lambda details via `boto3`.
2.  **Graph Construction**: Builds a `MultiDiGraph` where:
    - **Nodes**: Users, Roles, S3 Buckets, EC2 Instances, Lambda Functions.
    - **Edges**: Permissions (AssumeRole, PassRole), resource relationships (S3 Triggers), and exploitation vectors (IMDS Credential Theft).
3.  **Chain Proving**: Executes path-finding algorithms to identify sequences matching known attack tactics, such as the Capital One "Confused Deputy" pattern.

### Tactics Engine

Attack patterns are dynamically loaded from `rules/tactics.yaml`. This allows security teams to define custom escalation signatures without modifying the core engine.

---

## ⚖️ Compliance & Legality

Domino is built with a strict "100% legality" mandate. It performs read-only reconnaissance and logical analysis. It does not perform active exploitation, credential brute-forcing, or unauthorized access attempts.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
