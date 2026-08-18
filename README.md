# ARD Guard

**Pre-install provenance and policy firewall for agentic resources.**

ARD Guard inspects Agentic Resource Discovery (ARD) / AI Catalog metadata before an AI agent or developer connects to a Skill, MCP server, API, workflow, or other discovered capability.

It is deliberately focused on the trust gap *between discovery and execution*: source provenance, mutable references, risky installation instructions, excessive privileges, and incomplete publisher metadata.

> Status: early alpha. ARD is itself a draft specification, so this project favors fail-closed, explainable checks over pretending the ecosystem is already stable.

## Why

Agentic Resource Discovery makes it possible for agents to find capabilities dynamically. That is powerful, but discovery is not the same thing as trust. A resource can be relevant to a task and still be unsafe to install or connect.

ARD Guard provides a small, dependency-free gate that can run before installation or connection.

## What it checks

- insecure `http://` resource URLs
- mutable GitHub refs such as `/main`, `/master`, and `latest`
- pipe-to-shell install patterns such as `curl ... | sh` or `iwr ... | iex`
- unpinned package installation commands
- high-risk privilege indicators such as `sudo`, `--privileged`, `docker.sock`, and `chmod 777`
- missing publisher/operator/source metadata on resource-like objects

Every finding has a stable rule ID, severity, JSON path, and explanation.

## Quick start

```bash
python -m ard_guard scan catalog.json
python -m ard_guard scan catalog.json --format json
```

Exit codes:

- `0`: no blocking findings
- `1`: one or more findings
- `2`: invalid input or execution error

## Design goals

1. **Pre-install, not post-compromise.** Catch obvious trust failures before an agent wires in a resource.
2. **Explainable.** No opaque score without concrete findings.
3. **Provider-neutral.** Work with ARD/AI Catalog style JSON without requiring one vendor.
4. **Fail-closed where ambiguity is dangerous.** A mutable source reference should not be treated as equivalent to an immutable artifact.
5. **Automation-friendly.** Human-readable and JSON output, deterministic rule IDs, useful exit codes.

## Scope

ARD Guard is not a malware sandbox and does not claim to prove that a resource is safe. It is a policy and provenance gate. Deeper code analysis belongs to dedicated scanners; runtime containment belongs to sandboxes.

## Roadmap

- ARD v0.9 schema-aware resource extraction
- GitHub commit/tag resolution and lockfile generation
- publisher/domain provenance verification
- policy file with allow/deny rules
- SARIF output and GitHub Action
- MCP/Skill-specific adapters
- signed provenance / attestation checks
- registry diff monitoring

## License

Apache-2.0 is planned for the project. A license file will be added before the first tagged release.
