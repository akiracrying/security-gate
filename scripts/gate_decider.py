#!/usr/bin/env python3
"""
Gate decider: normalizes scanner results to a single finding schema,
applies policy + exceptions, and outputs allow/warn/block with GitHub summary.
Exit 0 = allow/warn, exit 1 = block.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str  # critical, high, medium, low, info
    path: str
    message: str
    fix_available: bool = False
    in_changed_files: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    def severity_order(self) -> int:
        o = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return o.get(self.severity.lower(), 5)


def load_yaml(path: Path) -> dict:
    if not yaml:
        raise RuntimeError("PyYAML required: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalize_severity(s: str) -> str:
    s = (s or "").lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    if s in ("error", "err"):
        return "high"
    if s in ("warning", "warn"):
        return "medium"
    return "medium"


def parse_gitleaks(path: Path) -> list[Finding]:
    findings = []
    data = load_json(path)
    for r in data.get("Findings", data) if isinstance(data, dict) else (data or []):
        rule = r.get("RuleID", "gitleaks")
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=rule,
                severity="high",
                path=r.get("File", r.get("SourceMetadata", {}).get("Data", {}).get("File", "")),
                message=r.get("Description", "Secret detected"),
                fix_available=False,
                in_changed_files=True,
                raw=r,
            )
        )
    return findings


def parse_sarif(path: Path) -> list[Finding]:
    findings = []
    data = load_json(path)
    runs = data.get("runs", [])
    for run in runs:
        tool_name = (run.get("tool", {}).get("driver", {}).get("name", "") or "sarif").lower()
        rules_map = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules_map.get(rule_id, {})
            severity = normalize_severity(
                result.get("level") or rule.get("defaultConfiguration", {}).get("level") or rule.get("properties", {}).get("security-severity") or "medium"
            )
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
            loc_path = (loc.get("artifactLocation", {}) or {}).get("uri", "")
            message = (result.get("message", {}).get("text") or result.get("message", {}).get("markdown") or str(result.get("message", "Finding")))
            if isinstance(message, dict):
                message = message.get("text", str(message))
            findings.append(
                Finding(
                    tool="codeql" if "codeql" in tool_name else ("semgrep" if "semgrep" in tool_name else tool_name),
                    rule_id=rule_id,
                    severity=severity,
                    path=loc_path,
                    message=message[:200],
                    fix_available=False,
                    in_changed_files=True,
                    raw=result,
                )
            )
    return findings


def parse_trivy(path: Path) -> list[Finding]:
    findings = []
    data = load_json(path)
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = normalize_severity(vuln.get("Severity", "unknown"))
            pkg = vuln.get("PkgName", "")
            vid = vuln.get("VulnerabilityID", vuln.get("ID", ""))
            fix = bool(vuln.get("FixedVersion"))
            path_str = result.get("Target", path.name)
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=vid,
                    severity=sev,
                    path=path_str,
                    message=f"{pkg}: {vuln.get('Title', vid)}",
                    fix_available=fix,
                    in_changed_files=True,
                    raw=vuln,
                )
            )
    return findings


def get_stage() -> str:
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    ref = os.environ.get("GITHUB_REF", "")
    if event == "pull_request":
        return "pr"
    if event == "workflow_dispatch" or (event == "push" and ref in ("refs/heads/main", "refs/heads/master")):
        return "release"
    return "pr"


def policy_decision(finding: Finding, stage: str, policy: dict) -> str:
    tool = finding.tool
    sev = finding.severity.lower()
    stage_policy = (policy.get("stages") or {}).get(stage) or {}

    if tool == "gitleaks":
        return (stage_policy.get("secrets") or {}).get("any", "block")

    if tool in ("codeql", "semgrep"):
        sast = stage_policy.get("sast") or {}
        if sev in ("critical", "high"):
            if stage == "pr":
                return sast.get("high_critical_high_confidence_in_changed", "warn") if finding.in_changed_files else sast.get("high_critical_otherwise", "warn")
            return sast.get("high_critical", "block")
        return sast.get("medium_low", "warn")

    if tool == "trivy":
        sca = stage_policy.get("sca") or {}
        if stage == "pr":
            return sca.get("any", "warn")
        if sev in ("critical", "high") and finding.fix_available:
            return sca.get("critical_high_runtime_with_fix", "block")
        return sca.get("dev_test_or_no_fix", "warn")

    if "dependency" in tool:
        dep = stage_policy.get("dependency_review") or {}
        if sev in ("critical", "high"):
            return dep.get("new_critical_high", "block")
        return dep.get("other", "warn")

    return "warn"


def apply_exceptions(finding: Finding, decision: str, exceptions: list[dict]) -> tuple[str, bool]:
    if decision != "block":
        return decision, False
    tool = finding.tool
    if tool == "gitleaks":
        return decision, False
    now = datetime.now(timezone.utc)
    for ex in exceptions:
        if ex.get("tool") != tool:
            continue
        match_val = ex.get("match", "")
        if not match_val:
            continue
        if match_val not in finding.rule_id and match_val not in finding.message:
            continue
        scope = ex.get("scope", "repo")
        if scope != "repo" and scope not in finding.path:
            continue
        expires_str = ex.get("expires")
        if not expires_str:
            continue
        try:
            exp = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if now < exp:
            return "warn", True
    return decision, False


def main() -> int:
    ap = argparse.ArgumentParser(description="Gate decider: normalize findings and output allow/warn/block")
    ap.add_argument("--gitleaks", type=Path, help="gitleaks JSON report")
    ap.add_argument("--sarif", type=Path, action="append", default=[], help="SARIF report (CodeQL/Semgrep)")
    ap.add_argument("--trivy", type=Path, help="Trivy JSON report")
    ap.add_argument("--policy", type=Path, default=Path("security/policy.yml"))
    ap.add_argument("--exceptions", type=Path, default=Path("security/exceptions.yml"))
    ap.add_argument("--stage", choices=("pr", "release"), default=None, help="Override stage (default: from env)")
    ap.add_argument("--export-latex", type=Path, help="Write policy mapping LaTeX table to file")
    args = ap.parse_args()

    repo_root = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    policy_path = repo_root / args.policy if not args.policy.is_absolute() else args.policy
    exceptions_path = repo_root / args.exceptions if not args.exceptions.is_absolute() else args.exceptions

    policy = load_yaml(policy_path) if policy_path.exists() else {}
    exceptions_list = []
    if exceptions_path.exists():
        exc_data = load_yaml(exceptions_path)
        if isinstance(exc_data, list):
            exceptions_list = exc_data
        else:
            exceptions_list = exc_data.get("exceptions", exc_data.get("entries", []))

    stage = args.stage or get_stage()
    all_findings: list[Finding] = []

    if args.gitleaks and args.gitleaks.exists():
        all_findings.extend(parse_gitleaks(args.gitleaks))
    for p in args.sarif:
        if p.exists():
            all_findings.extend(parse_sarif(p))
    if args.trivy and args.trivy.exists():
        all_findings.extend(parse_trivy(args.trivy))

    decisions: list[tuple[Finding, str, bool]] = []
    for f in all_findings:
        dec = policy_decision(f, stage, policy)
        dec, exc_applied = apply_exceptions(f, dec, exceptions_list)
        decisions.append((f, dec, exc_applied))

    blocks = [d for d in decisions if d[1] == "block"]
    warns = [d for d in decisions if d[1] == "warn"]
    allows = [d for d in decisions if d[1] == "allow"]

    summary_lines = [
        "# Security gate summary",
        "",
        f"**Stage:** {stage}",
        f"**Allow:** {len(allows)} | **Warn:** {len(warns)} | **Block:** {len(blocks)}",
        "",
    ]
    if blocks:
        summary_lines.append("## Blocked findings")
        for f, _, exc in blocks:
            summary_lines.append(f"- **{f.tool}** [{f.severity}] {f.rule_id}: {f.path}")
        summary_lines.append("")
    if warns:
        summary_lines.append("## Warnings")
        for f, _, exc in warns:
            suffix = " (exception applied)" if exc else ""
            summary_lines.append(f"- **{f.tool}** [{f.severity}] {f.rule_id}: {f.path}{suffix}")
        summary_lines.append("")
    exc_applied_list = [d for d in decisions if d[2]]
    if exc_applied_list:
        summary_lines.append("## Exceptions applied")
        for f, _, _ in exc_applied_list:
            summary_lines.append(f"- {f.tool} / {f.rule_id} in {f.path}")
        summary_lines.append("")

    summary_md = "\n".join(summary_lines)
    print(summary_md)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "w", encoding="utf-8") as f:
            f.write(summary_md)

    for f, _, exc in warns:
        msg = f"{f.tool} [{f.severity}] {f.rule_id}: {f.path}"
        if exc:
            msg += " (exception applied)"
        print(f"::warning::{msg}", flush=True)

    if args.export_latex:
        write_latex_table(args.export_latex, decisions, stage)

    return 1 if blocks else 0


def write_latex_table(out_path: Path, decisions: list[tuple[Finding, str, bool]], stage: str) -> None:
    sample = [
        ("Gitleaks secret", "Block"),
        ("CodeQL high SQLi", "Block"),
        ("Semgrep medium header", "Warn"),
        ("Trivy CRITICAL runtime with fix", "Block (release)"),
        ("Trivy dev dependency no fix", "Warn+exception"),
        ("CodeQL medium in unchanged file (PR)", "Warn"),
        ("Dependency-review new HIGH", "Block (PR)"),
    ]
    lines = [
        r"\begin{tabular}{lll}",
        r"\toprule",
        r"Tool / Finding & Stage & Decision \\",
        r"\midrule",
    ]
    for tool_finding, decision in sample:
        lines.append(f"{tool_finding} & {stage} & {decision} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
