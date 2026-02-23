# Security Gates (Pass–Warn–Block)

This document describes the security gates pipeline for the repository: stages, tools, decision model, exceptions, and the Gate Pressure Score.

## Stages

| Stage | Trigger | Purpose |
|-------|---------|---------|
| **PR** | `pull_request` | Fast feedback; minimal blocking. Block only on verified secrets and high-confidence SAST in changed code. Everything else is **warn**. |
| **Release / main** | `push` to `main`, `workflow_dispatch` | Strict gates. Block on all secrets, high/critical SAST (CodeQL + Semgrep), CRITICAL/HIGH SCA in runtime deps with fix, and CRITICAL/HIGH container image issues with fix. |

## Tools

| Class | Tool | PR | Release/main |
|-------|-----|----|--------------|
| **Secrets** | Gitleaks | block verified patterns; warn potential/entropy | block all |
| **SAST** | CodeQL | — | block on high/critical |
| **SAST** | Semgrep | warn (block high-confidence categories in changed files) | block high/critical |
| **SCA** | Trivy FS / image | warn | block CRITICAL/HIGH runtime with fix; warn dev/no-fix |
| **SCA** | OWASP Dependency-Check | — | block CRITICAL/HIGH runtime with fix; warn dev/no-fix |
| **Dependencies** | dependency-review-action | warn / block on new critical/high | — |
| **Container** | Trivy image | warn (if image built) | block CRITICAL/HIGH with fix |

All runs use only popular, open-source tools that produce SARIF or JSON and run on GitHub-hosted runners without external services. Only `GITHUB_TOKEN` with minimal permissions is used.

## Allow / Warn / Block

- **Allow**: No finding or finding below policy threshold. Job succeeds, no warning.
- **Warn**: Finding above "ignore" threshold but not blocking for this stage. Job **succeeds** (exit 0). Output includes `::warning::` and a summary; artifacts (SARIF/JSON) are uploaded.
- **Block**: Finding meets blocking criteria. Job **fails** (exit 1). Same artifacts and summary, but merge/release must not proceed until fixed or (where allowed) a time-boxed exception is added.

## Secrets: Verified vs Potential

Gitleaks findings are classified by **confidence**:

- **Verified** (confidence=high): known key patterns (AWS keys, GitHub PATs, Slack tokens, JWTs, etc.) — always **block**.
- **Potential** (confidence=medium): high-entropy strings or generic patterns — **warn on PR**, **block on release**.

This avoids "everything is red" noise on PRs while keeping release strict. No exceptions are ever allowed for secrets.

## SAST: High-Confidence Blocking Rules

On PR, SAST only blocks findings that match **high-confidence categories** in changed files: SQL injection, code injection, command injection, path traversal, XSS, XXE, unsafe deserialization, zip-slip, prototype pollution. Medium/low findings or findings outside changed files are always warn.

On Release, all high/critical SAST findings block regardless of category.

## SCA: Runtime vs Dev Dependencies

SCA findings are classified by **dependency scope** (runtime, dev, unknown):

- **Runtime** + fix available + high/critical → **block on release**, warn on PR.
- **Dev** dependencies → always **warn** (can be managed via exceptions).
- No fix available → **warn** + time-boxed exception recommended.

## Gate Pressure Score

Each run produces a letter grade (A+ through D) based on a weighted score:

| Decision | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Block | 10 pts | 5 pts | 2 pts | 1 pt |
| Warn | 0.5 pts | 0.5 pts | 0.5 pts | 0.5 pts |

| Grade | Score range |
|-------|------------|
| A+ | 0 |
| A | 1–10 |
| B | 11–50 |
| C | 51–150 |
| D | > 150 |

This is an **operational metric** for tracking security debt and gate calibration over time, not a risk quantification. A high score signals the need for remediation or exception review.

## Exceptions (Time-Bound Risk Acceptance)

File: `security/exceptions.yml`.

Format: list of entries with `id`, `tool`, `match` (CVE ID or rule ID), `scope` (repo/path), `reason`, `owner`, `expires` (ISO date).

If a finding matches an exception and `expires` is in the future: **block → warn** and the summary shows "exception applied". If expired, the finding blocks again. Exceptions are **never** allowed for secrets.

## Demo: Synthetic Secret

The file `demo/juice-shop-master/demo/FAKE_SECRET.txt` is a **synthetic secret for demonstrating gate behavior** only. Real secrets are never allowed. It is allowlisted in `security/gitleaks.toml` so that `main` stays clean.

## Pipeline Overview

- **PR**: Checkout → Gitleaks (block verified / warn potential) → Semgrep (warn; block high-confidence in changed) → SCA Trivy (warn) → Dependency review (warn/block) → gate_decider summary → upload SARIF/JSON.
- **Release**: Checkout → Gitleaks (block all) → CodeQL (block high/critical) → Semgrep (block high/critical) → SCA Trivy FS+image (block runtime with fix) → Dependency-Check (block runtime with fix) → gate_decider summary → upload artifacts.

See `docs/pipeline_diagram.png` for a visual of stages and gate placement.
