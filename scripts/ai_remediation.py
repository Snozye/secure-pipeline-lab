#!/usr/bin/env python3
"""
Security Findings Reporter
Parses findings from Semgrep, Gitleaks, or Trivy and posts a summary comment on the PR.

Set TOOL=semgrep|gitleaks|trivy.
"""

import json
import os
import sys
import requests

SARIF_PATH = "semgrep-findings.sarif"
GITLEAKS_PATH = "gitleaks-report.json"
TRIVY_PATH = "trivy-findings.json"
ZAP_PATH = "report_json.json"

TOOL = os.environ.get("TOOL", "all")
COMMENT_MARKER = f"<!-- security-findings-{TOOL} -->"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_semgrep(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        sarif = json.load(f)

    seen, findings = set(), []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            rule_name = rule.get("shortDescription", {}).get("text", "") or rule_id
            severity = result.get("level", "warning").upper()
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                try:
                    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                    line = loc["physicalLocation"]["region"]["startLine"]
                except KeyError:
                    continue
                key = (rule_id, uri, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "tool": "semgrep",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "filepath": uri,
                    "line": line,
                    "severity": severity,
                    "message": message,
                })
    return findings


def parse_gitleaks(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []
    if not data:
        return []

    findings = []
    for item in data:
        findings.append({
            "tool": "gitleaks",
            "rule_id": item.get("RuleID", "unknown"),
            "rule_name": item.get("Description", item.get("RuleID", "unknown")),
            "filepath": item.get("File", "unknown"),
            "line": item.get("StartLine", 1),
            "severity": "HIGH",
            "message": item.get("Match", ""),
            "commit": item.get("Commit", ""),
            "author": item.get("Author", ""),
            "date": item.get("Date", ""),
        })
    return findings


def parse_zap(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    findings = []
    for alert in data.get("site", [{}])[0].get("alerts", []):
        risk = alert.get("riskdesc", "").split(" ")[0].upper()
        findings.append({
            "tool": "zap",
            "rule_id": alert.get("pluginid", "unknown"),
            "rule_name": alert.get("alert", "unknown"),
            "severity": risk if risk in SEV_ORDER else "MEDIUM",
            "confidence": alert.get("confidence", ""),
            "description": alert.get("desc", "").replace("<p>", "").replace("</p>", " ").strip()[:300],
            "solution": alert.get("solution", "").replace("<p>", "").replace("</p>", " ").strip()[:300],
            "reference": alert.get("reference", ""),
            "instances": [
                {"uri": i.get("uri", ""), "method": i.get("method", ""), "evidence": i.get("evidence", "")[:100]}
                for i in alert.get("instances", [])[:5]
            ],
            "count": alert.get("count", len(alert.get("instances", []))),
        })
    return findings


def parse_trivy(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        if target.endswith(".sarif") or target.endswith(".json"):
            continue
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy",
                "type": "vuln",
                "rule_id": vuln.get("VulnerabilityID", "unknown"),
                "rule_name": vuln.get("Title", vuln.get("PkgName", "unknown")),
                "filepath": target,
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "pkg_name": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "message": vuln.get("Description", ""),
                "reference": vuln.get("PrimaryURL", ""),
            })
        for secret in result.get("Secrets", []):
            findings.append({
                "tool": "trivy",
                "type": "secret",
                "rule_id": secret.get("RuleID", "unknown"),
                "rule_name": secret.get("Title", secret.get("Category", "unknown")),
                "filepath": target,
                "line": secret.get("StartLine", 1),
                "severity": secret.get("Severity", "HIGH").upper(),
                "message": secret.get("Match", ""),
            })
    return findings


# ---------------------------------------------------------------------------
# Comment builder
# ---------------------------------------------------------------------------

SEV_EMOJI = {
    "CRITICAL": "🔴", "ERROR": "🔴", "HIGH": "🟠",
    "WARNING": "🟡", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪", "UNKNOWN": "⚪",
}

SEV_ORDER = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3, "MEDIUM": 4, "LOW": 5, "INFO": 6, "UNKNOWN": 7}

TOOL_LABELS = {
    "semgrep": "🔍 Semgrep SAST",
    "gitleaks": "🔑 Gitleaks Secrets",
    "trivy": "📦 Trivy SCA / Secrets",
    "zap": "🌐 OWASP ZAP DAST",
}


def build_semgrep_comment(findings: list[dict]) -> str:
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    lines = [
        COMMENT_MARKER,
        f"## {TOOL_LABELS['semgrep']} — {len(findings)} finding(s)",
        "",
        "| Severity | Rule | File | Line |",
        "|----------|------|------|------|",
    ]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        rule_link = f"`{f['rule_id']}`"
        lines.append(f"| {emoji} {f['severity']} | {rule_link} | `{f['filepath']}` | {f['line']} |")

    lines += ["", "---", ""]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        lines.append(f"### {emoji} `{f['rule_id']}`")
        lines.append(f"**File:** `{f['filepath']}:{f['line']}`  ")
        lines.append(f"**Severity:** {f['severity']}  ")
        lines.append(f"**Rule:** {f['rule_name']}")
        if f.get("message"):
            lines.append(f"> {f['message'][:300]}")
        lines.append("")

    lines += [
        "---",
        "*Check the [Actions log](${{ github.server_url }}/${{ github.repository }}/actions) for full details.*",
    ]
    return "\n".join(lines)


def build_gitleaks_comment(findings: list[dict]) -> str:
    lines = [
        COMMENT_MARKER,
        f"## {TOOL_LABELS['gitleaks']} — {len(findings)} finding(s)",
        "",
        "| Severity | Rule | File | Line |",
        "|----------|------|------|------|",
    ]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        lines.append(f"| {emoji} {f['severity']} | `{f['rule_id']}` | `{f['filepath']}` | {f['line']} |")

    lines += ["", "---", ""]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        lines.append(f"### {emoji} `{f['rule_id']}` — {f['rule_name']}")
        lines.append(f"**File:** `{f['filepath']}:{f['line']}`")
        if f.get("commit"):
            lines.append(f"**Commit:** `{f['commit'][:8]}`")
        if f.get("author"):
            lines.append(f"**Author:** {f['author']}")
        if f.get("date"):
            lines.append(f"**Date:** {f['date']}")
        if f.get("message"):
            lines.append(f"**Match (redacted):** `{f['message'][:80]}`")
        lines.append("")

    lines += ["---", "*Rotate any exposed secrets immediately.*"]
    return "\n".join(lines)


def build_trivy_comment(findings: list[dict]) -> str:
    vulns = sorted([f for f in findings if f.get("type") == "vuln"], key=lambda f: SEV_ORDER.get(f["severity"], 9))
    secrets = [f for f in findings if f.get("type") == "secret"]

    lines = [
        COMMENT_MARKER,
        f"## {TOOL_LABELS['trivy']} — {len(findings)} finding(s)",
        f"**{len(vulns)} vulnerabilities · {len(secrets)} secrets**",
        "",
    ]

    if vulns:
        lines += [
            "### Vulnerabilities",
            "",
            "| Severity | CVE | Package | Installed | Fixed |",
            "|----------|-----|---------|-----------|-------|",
        ]
        for f in vulns:
            emoji = SEV_EMOJI.get(f["severity"], "⚪")
            cve = f"[{f['rule_id']}]({f['reference']})" if f.get("reference") else f"`{f['rule_id']}`"
            fixed = f"`{f['fixed_version']}`" if f.get("fixed_version") else "—"
            lines.append(f"| {emoji} {f['severity']} | {cve} | `{f['pkg_name']}` | `{f['installed_version']}` | {fixed} |")
        lines.append("")

    if secrets:
        lines += [
            "### Secrets",
            "",
            "| Severity | Rule | File | Line |",
            "|----------|------|------|------|",
        ]
        for f in secrets:
            emoji = SEV_EMOJI.get(f["severity"], "⚪")
            lines.append(f"| {emoji} {f['severity']} | `{f['rule_id']}` | `{f['filepath']}` | {f.get('line', '—')} |")
        lines.append("")

    lines += ["---", "*Check the Actions log for full details.*"]
    return "\n".join(lines)


def build_zap_comment(findings: list[dict]) -> str:
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    lines = [
        COMMENT_MARKER,
        f"## {TOOL_LABELS['zap']} — {len(findings)} alert(s)",
        "",
        "| Severity | Alert | Instances |",
        "|----------|-------|-----------|",
    ]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        lines.append(f"| {emoji} {f['severity']} | {f['rule_name']} | {f['count']} |")

    lines += ["", "---", ""]
    for f in findings:
        emoji = SEV_EMOJI.get(f["severity"], "⚪")
        lines.append(f"### {emoji} {f['rule_name']}")
        lines.append(f"**Plugin ID:** `{f['rule_id']}` · **Confidence:** {f['confidence']} · **Instances:** {f['count']}")
        lines.append("")
        if f.get("description"):
            lines.append(f"**Description:** {f['description']}")
            lines.append("")
        if f.get("solution"):
            lines.append(f"**Solution:** {f['solution']}")
            lines.append("")
        if f.get("instances"):
            lines.append("<details>")
            lines.append("<summary>Affected URLs</summary>")
            lines.append("")
            for inst in f["instances"]:
                evidence = f" — `{inst['evidence']}`" if inst.get("evidence") else ""
                lines.append(f"- `{inst['method']} {inst['uri']}`{evidence}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    lines += ["---", "*Check the Actions log for the full HTML report.*"]
    return "\n".join(lines)


def build_comment(findings: list[dict], tool_name: str) -> str:
    if tool_name == "semgrep":
        return build_semgrep_comment(findings)
    if tool_name == "gitleaks":
        return build_gitleaks_comment(findings)
    if tool_name == "trivy":
        return build_trivy_comment(findings)
    if tool_name == "zap":
        return build_zap_comment(findings)
    return f"{COMMENT_MARKER}\n## Security Findings\n\n{len(findings)} finding(s) found."


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

def delete_previous_comments(token: str, repo: str, pr_number: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = requests.get(url, headers=headers, params={"per_page": 100})
    resp.raise_for_status()
    for comment in resp.json():
        if COMMENT_MARKER in comment.get("body", ""):
            requests.delete(
                f"https://api.github.com/repos/{repo}/issues/comments/{comment['id']}",
                headers=headers,
            )
            print(f"Deleted previous comment {comment['id']}")


def post_pr_comment(body: str) -> None:
    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]

    delete_previous_comments(token, repo, pr_number)

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = requests.post(url, headers=headers, json={"body": body})
    resp.raise_for_status()
    print(f"Posted comment: {resp.json()['html_url']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parsers = {
        "semgrep": lambda: parse_semgrep(SARIF_PATH),
        "gitleaks": lambda: parse_gitleaks(GITLEAKS_PATH),
        "trivy": lambda: parse_trivy(TRIVY_PATH),
        "zap": lambda: parse_zap(ZAP_PATH),
    }

    if TOOL in parsers:
        findings = parsers[TOOL]()
        tool_name = TOOL
    else:
        print(f"Unknown TOOL={TOOL}. Use semgrep, gitleaks, or trivy.")
        sys.exit(1)

    if not findings:
        print(f"No findings for {TOOL}.")
        sys.exit(0)

    print(f"{len(findings)} finding(s) [{TOOL}]")
    for f in findings:
        loc = f":{f['line']}" if f.get("line") else ""
        location = f.get("filepath") or f.get("rule_name", "")
        print(f"  {f['severity']} {f['rule_id']} @ {location}{loc}")

    comment = build_comment(findings, tool_name)

    if os.environ.get("PR_NUMBER"):
        post_pr_comment(comment)
    else:
        print("\n--- COMMENT PREVIEW ---\n")
        print(comment)


if __name__ == "__main__":
    main()
