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
    raw_list = data.get("Findings", data.get("findings", data)) if isinstance(data, dict) else (data or [])
    if not isinstance(raw_list, list):
        raw_list = []
    for r in raw_list:
        rule = r.get("RuleID", "gitleaks")
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=rule,
                severity="high",
                path=r.get("File", r.get("SourceMetadata", {}).get("Data", {}).get("File", r.get("file", ""))),
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


def parse_dependency_check(path: Path) -> list[Finding]:
    findings = []
    data = load_json(path)
    deps = data.get("dependencies", data.get("dependency", []))
    if not isinstance(deps, list):
        deps = []
    for dep in deps:
        for vuln in dep.get("vulnerabilities", []) or []:
            sev = normalize_severity(vuln.get("severity", "medium"))
            name = vuln.get("name", vuln.get("cve", "CVE-?"))
            findings.append(
                Finding(
                    tool="dependency-check",
                    rule_id=name,
                    severity=sev,
                    path=dep.get("fileName", path.name),
                    message=vuln.get("description", name)[:200],
                    fix_available=bool(dep.get("evidenceCollected", {}).get("versionEvidence")),
                    in_changed_files=True,
                    raw=vuln,
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

    if tool in ("trivy", "dependency-check"):
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
    ap.add_argument("--trivy", type=Path, action="append", default=[], help="Trivy JSON report(s) (FS + image)")
    ap.add_argument("--depcheck", type=Path, help="OWASP Dependency-Check JSON report")
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

    def _fsize(p: Path) -> str:
        try:
            return f"{p.stat().st_size} bytes"
        except Exception:
            return "?"

    if args.gitleaks:
        exists = args.gitleaks.exists()
        print(f"::notice::gitleaks report: {args.gitleaks} exists={exists} size={_fsize(args.gitleaks) if exists else 'N/A'}", flush=True)
        if exists:
            gl = parse_gitleaks(args.gitleaks)
            print(f"::notice::gitleaks parsed: {len(gl)} findings", flush=True)
            all_findings.extend(gl)
    for p in args.sarif:
        if p.exists():
            sf = parse_sarif(p)
            print(f"::notice::sarif {p.name}: {len(sf)} findings ({_fsize(p)})", flush=True)
            all_findings.extend(sf)
    for trivy_path in args.trivy or []:
        if trivy_path and trivy_path.exists():
            tf = parse_trivy(trivy_path)
            print(f"::notice::trivy {trivy_path.name}: {len(tf)} findings ({_fsize(trivy_path)})", flush=True)
            all_findings.extend(tf)
    if args.depcheck:
        exists = args.depcheck.exists()
        print(f"::notice::depcheck report: {args.depcheck} exists={exists} size={_fsize(args.depcheck) if exists else 'N/A'}", flush=True)
        if exists:
            dc = parse_dependency_check(args.depcheck)
            print(f"::notice::depcheck parsed: {len(dc)} findings", flush=True)
            all_findings.extend(dc)
        else:
            import glob as _g
            candidates = _g.glob("reports/*dependency*") + _g.glob("reports/*security*")
            print(f"::notice::depcheck file not found; candidates in reports/: {candidates}", flush=True)

    decisions: list[tuple[Finding, str, bool]] = []
    for f in all_findings:
        dec = policy_decision(f, stage, policy)
        dec, exc_applied = apply_exceptions(f, dec, exceptions_list)
        decisions.append((f, dec, exc_applied))

    blocks = [d for d in decisions if d[1] == "block"]
    warns = [d for d in decisions if d[1] == "warn"]
    allows = [d for d in decisions if d[1] == "allow"]

    tools_order = ["gitleaks", "codeql", "semgrep", "trivy", "dependency-check"]

    by_tool: dict[str, int] = {}
    for f, _, _ in decisions:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
    by_tool_decision: dict[str, tuple[int, int, int]] = {}
    for f, dec, _ in decisions:
        if f.tool not in by_tool_decision:
            by_tool_decision[f.tool] = (0, 0, 0)
        a, w, b = by_tool_decision[f.tool]
        if dec == "allow":
            by_tool_decision[f.tool] = (a + 1, w, b)
        elif dec == "warn":
            by_tool_decision[f.tool] = (a, w + 1, b)
        else:
            by_tool_decision[f.tool] = (a, w, b + 1)

    summary_lines = [
        "# Security gate summary",
        "",
        f"**Stage:** {stage}  |  **Allow:** {len(allows)}  |  **Warn:** {len(warns)}  |  **Block:** {len(blocks)}",
        "",
        "## Counts by tool",
        "",
        "| Tool | Allow | Warn | Block | Total |",
        "|------|-------|------|-------|-------|",
    ]
    for t in tools_order:
        al, wa, bl = by_tool_decision.get(t, (0, 0, 0))
        total = by_tool.get(t, 0)
        summary_lines.append(f"| {t} | {al} | {wa} | {bl} | {total} |")
    summary_lines.append("")

    all_for_table = [(f, dec, exc) for f, dec, exc in (blocks + warns)]
    max_rows = 80
    summary_lines.append("## Findings (Tool | Severity | Rule/ID | Path | Decision)")
    summary_lines.append("")
    summary_lines.append("| Tool | Severity | Rule/ID | Path | Decision |")
    summary_lines.append("|------|----------|---------|------|----------|")
    for f, dec, exc in all_for_table[:max_rows]:
        path_short = ((f.path or "").replace("|", "/")[:60]) + ("…" if len((f.path or "")) > 60 else "")
        rule_short = ((f.rule_id or "").replace("|", ",")[:40]) + ("…" if len((f.rule_id or "")) > 40 else "")
        exc_s = " (exception)" if exc else ""
        summary_lines.append(f"| {f.tool} | {f.severity} | {rule_short} | {path_short} | {dec}{exc_s} |")
    if len(all_for_table) > max_rows:
        summary_lines.append(f"| … | … | … | _+{len(all_for_table) - max_rows} more_ | … |")
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
