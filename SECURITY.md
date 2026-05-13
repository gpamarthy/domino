# Security policy

## Supported versions

Pre-1.0, only the latest tagged release receives security fixes.

## Reporting a vulnerability

**Do not file public issues for security problems.**

Email a description and reproduction to the maintainer. Expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for issues that can be reproduced.

If no response in 14 days, you are free to disclose publicly.

## Scope

In scope:

- Vulnerabilities in domino itself (RCE in the analyzer, credential leakage in snapshots, path traversal in JSON output)
- False negatives where a real IAM privilege-escalation chain is missed
- Mishandling of AWS credentials by the recon code

Out of scope:

- Vulnerabilities or misconfigurations in the AWS accounts being scanned. Those are the findings the tool is built to surface.
- Vulnerabilities in `boto3`, `networkx`, or other upstream dependencies. Report to the respective project.
- Use of the tool on accounts you do not have written authorization to test. The tool refuses to run without an explicit profile or assume-role context, but the operator is responsible for authorization.

## Operator note

`domino` reads IAM and resource policies. It does not modify anything. Even so, only run it against accounts where you have explicit authorization. The bundled `--demo` snapshot is safe to explore offline.
