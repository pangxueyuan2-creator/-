# Security Policy

ARD Guard is a security-sensitive project. Reports that could enable exploitation of users should be disclosed privately rather than posted as a public proof-of-concept.

## Supported versions

The project is pre-1.0. Until the first tagged release, only the current `main` branch is supported.

## Reporting

When reporting a vulnerability, include:

- affected commit or version
- exact input that triggers the issue, minimized where possible
- expected versus actual result
- security impact, especially false-negative or fail-open behavior
- whether the issue can cause code execution, secret disclosure, provenance bypass, identity confusion, or policy bypass

Do not include live credentials, private tokens, or unrelated user data in reports.

## Security design principles

- fail closed when trust metadata is ambiguous
- never execute scanned installation instructions
- never execute or import scanned repository content during verification
- treat catalog, ARD, Agent Finder, MCP, and Agent Skill metadata as untrusted input
- bind explicit publisher/namespace identity claims to declared source provenance where the relationship can be checked deterministically
- do not guess that a free-form brand/publisher name is a GitHub identity
- keep findings deterministic and explainable
- avoid network access in the default scanner path
- keep any future network-backed provenance resolution opt-in and side-effect free
- pin CI dependencies to immutable commits
