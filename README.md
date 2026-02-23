# security-gate

Security gate pipeline project: **pass–warn–block** quality gates on top of OWASP Juice Shop as a demo target.

## Security Gates Demo

This repo implements **security gates as quality gates** (pass / warn / block) with a stage-aware policy:

- **PR stage** (`pull_request`): Fast feedback; blocks only on confirmed secrets and (optionally) high-confidence SAST in changed code. SAST/SCA and dependency review otherwise **warn** (job stays green, summary shows warnings).
- **Release stage** (`push` to `main`, `workflow_dispatch`): Strict gates; block on secrets, CodeQL high/critical, SCA CRITICAL/HIGH in runtime deps with fix, and container image CRITICAL/HIGH with fix. Time-boxed **exceptions** turn block → warn and are listed in the summary.

**What is demonstrated:**

- **Pass**: No findings or below threshold → job succeeds.
- **Warn**: Findings above “ignore” but not blocking → job succeeds, `::warning::` and summary; no merge block.
- **Block**: Findings that meet blocking policy → job fails (exit 1); merge/release blocked until fix or (where allowed) an exception in `security/exceptions.yml`.
- **Stage-aware policy**: Different rules for PR vs release (see `security/policy.yml` and [docs/SECURITY_GATES.md](docs/SECURITY_GATES.md)).
- **Exceptions**: Time-bound risk acceptance in `security/exceptions.yml`; expired exceptions revert to block.

**Tools:** Gitleaks (secrets), CodeQL (SAST on release), Semgrep (SAST on PR), Trivy (SCA + optional container), Dependency Review. All run on GitHub-hosted runners with `GITHUB_TOKEN` only; SARIF/JSON reports are uploaded as artifacts.

Full description: [docs/SECURITY_GATES.md](docs/SECURITY_GATES.md).
