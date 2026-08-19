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
- unpinned package installation commands, including installs hidden behind `sudo`
- high-risk privilege indicators such as `sudo`, `--privileged`, `docker.sock`, and `chmod 777`
- possible environment-secret collection followed by external transmission
- missing publisher/operator/source metadata on resource-like objects
- contradictions between an explicit GitHub publisher identity or verified-style MCP `io.github.<owner>/...` namespace and the GitHub owner that actually hosts the declared source

Every finding has a stable rule ID, severity, JSON path, and explanation.

### Provenance identity binding

Rule `AG009` is an offline anti-impersonation check. It compares only strong identity claims that can be interpreted without guessing:

- explicit identities such as `github:trusted-org`, `@trusted-org`, or `https://github.com/trusted-org`
- MCP Registry-style names such as `io.github.trusted-org/server-name`

If the same resource points at a GitHub repository owned by a different account, ARD Guard reports a high-severity provenance conflict. Free-form publisher names are intentionally not coerced into GitHub usernames, which keeps the rule deterministic and avoids turning brand names into speculative identity claims.

This check is useful at the discovery-to-connection boundary used by ARD and Agent Finder, and for MCP/Agent Skill metadata that ultimately points at GitHub-hosted code. It performs no network requests and never executes scanned instructions or repository content.

## Quick start

```bash
python -m pip install -e .
python -m ard_guard scan examples/safe.json
python -m ard_guard scan examples/risky.json
python -m ard_guard scan catalog.json --format json
```

Exit codes:

- `0`: no findings
- `1`: one or more findings
- `2`: invalid input or execution error

## Design goals

1. **Pre-install, not post-compromise.** Catch obvious trust failures before an agent wires in a resource.
2. **Explainable.** No opaque score without concrete findings.
3. **Provider-neutral.** Work with ARD/AI Catalog style JSON without requiring one vendor.
4. **Fail-closed where ambiguity is dangerous.** A mutable source reference should not be treated as equivalent to an immutable artifact.
5. **Automation-friendly.** Human-readable and JSON output, deterministic rule IDs, useful exit codes.
6. **Safe by construction.** Scanning never executes installation instructions or scanned repository content.

## Scope

ARD Guard is not a malware sandbox and does not claim to prove that a resource is safe. It is a policy and provenance gate. Deeper code analysis belongs to dedicated scanners; runtime containment belongs to sandboxes.

## Roadmap

The tracked roadmap lives in GitHub issue #1. Major targets include:

- ARD v0.9 schema-aware resource extraction
- GitHub commit/tag resolution and lockfile generation
- publisher/domain provenance verification
- policy file with allow/deny rules
- SARIF output and GitHub Action
- MCP/Skill-specific adapters
- signed provenance / attestation checks
- registry diff monitoring

## License

Apache License 2.0. See `LICENSE`.
