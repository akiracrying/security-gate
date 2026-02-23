# Security Gates (Pass–Warn–Block)

This document describes the security gates pipeline for the repository: stages, tools, decision model, and exceptions.

## Stages

| Stage | Trigger | Purpose |
|-------|---------|---------|
| **PR** | `pull_request` | Fast feedback; minimal blocking. Block only on confirmed secrets and (optionally) high-confidence SAST in changed code. Everything else is **warn**. |
| **Release / main** | `push` to `main`, `workflow_dispatch` | Strict gates. Block on secrets, high/critical SAST (CodeQL), CRITICAL/HIGH SCA in runtime deps with fix, and CRITICAL/HIGH container image issues with fix. Exceptions allowed only as time-boxed risk acceptance (block→warn). |

## Tools

| Class | Tool | PR | Release/main |
|-------|-----|----|--------------|
| **Secrets** | Gitleaks | block on any finding | block on any finding |
| **SAST** | CodeQL | — | block on high/critical |
| **SAST** | Semgrep | warn (optional; high-confidence in changed files can block) | — |
| **SCA** | Trivy FS / OSV-Scanner | warn | block CRITICAL/HIGH runtime with fix |
| **Dependencies** | dependency-review-action | warn / block on new critical/high | — |
| **Container** | Trivy image | warn (if image built) | block CRITICAL/HIGH with fix |

All runs use only popular, open-source tools that produce SARIF or JSON and run on GitHub-hosted runners without external services. Only `GITHUB_TOKEN` with minimal permissions is used.

## Allow / Warn / Block

- **Allow**: No finding or finding below policy threshold. Job succeeds, no warning.
- **Warn**: Finding above “ignore” threshold but not blocking for this stage. Job **succeeds** (exit 0). Output includes `::warning::` and a summary; artifacts (SARIF/JSON) are uploaded.
- **Block**: Finding meets blocking criteria. Job **fails** (exit 1). Same artifacts and summary, but merge/release must not proceed until fixed or (where allowed) a time-boxed exception is added.

Secrets: any confirmed secret is **always block** on both stages. No exceptions for secrets.

## Exceptions (Time-Bound Risk Acceptance)

File: `security/exceptions.yml`.

Format: list of entries with:

- `id`, `tool`, `match` (e.g. CVE ID or rule ID), `scope` (repo/path), `reason`, `owner`, `expires` (ISO date).

If a finding matches an exception and `expires` is in the future: **block → warn** and the summary shows “exception applied”. If the exception has expired, the finding is treated as block again.

- **PR**: Exceptions allowed for SCA “no fix” and for SAST medium/low. **Never for secrets.**
- **Release/main**: Exceptions allowed per policy; they are always listed in the summary and result in warn, not block.

## Demo: Synthetic Secret

The file `demo/juice-shop-master/demo/FAKE_SECRET.txt` is a **synthetic secret for demonstrating gate behavior** only. Real secrets are never allowed. It is allowlisted in `security/gitleaks.toml` and `.gitleaksignore` so that `main` stays clean.

## Pipeline Overview

- **PR**: Checkout → Gitleaks (block) → Semgrep/SAST (warn; optional block for high-confidence in changed files) → SCA (warn) → Dependency review (warn/block by policy) → gate_decider summary → upload SARIF/JSON.
- **Release**: Checkout → Gitleaks (block) → CodeQL (block high/critical) → SCA Trivy/OSV (block CRITICAL/HIGH runtime with fix) → [optional] container scan (block CRITICAL/HIGH with fix) → gate_decider summary → upload artifacts.

See `docs/pipeline_diagram.png` for a visual of stages and gate placement.
