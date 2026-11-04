#!/usr/bin/env python3
"""
AI Remediation Advisor
Analyzes findings from Semgrep, Gitleaks, and Trivy using abliteration.ai
and posts a consolidated remediation comment on the PR.
"""

import json
import os
import sys
import requests

SARIF_PATH = "semgrep-findings.sarif"
GITLEAKS_PATH = "gitleaks-findings.json"
TRIVY_PATH = "trivy-findings.json"

CONTEXT_LINES = 8
COMMENT_MARKER = "<!-- ai-remediation-advisor -->"
MODEL = "abliterated-model"
API_URL = "https://api.abliteration.ai/v1/chat/completions"


# ---------------------------------------------------------------------------
# Code context
# ---------------------------------------------------------------------------

def read_code_context(filepath: str, line: int) -> str:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line - CONTEXT_LINES - 1)
        end = min(len(lines), line + CONTEXT_LINES)
        numbered = []
        for i, l in enumerate(lines[start:end], start=start + 1):
            marker = "→" if i == line else " "
            numbered.append(f"{i:4} {marker} {l.rstrip()}")
        return "\n".join(numbered)
    except FileNotFoundError:
        return f"(file not found: {filepath})"


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
                    "extra": None,
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
            "extra": item.get("Match", ""),
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
        for secret in result.get("Secrets", []):
            findings.append({
                "tool": "trivy",
                "rule_id": secret.get("RuleID", "unknown"),
                "rule_name": secret.get("Title", secret.get("Category", "unknown")),
                "filepath": target,
                "line": secret.get("StartLine", 1),
                "severity": secret.get("Severity", "HIGH").upper(),
                "extra": secret.get("Match", ""),
            })
    return findings


# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------

def build_prompt(finding: dict) -> str:
    tool = finding["tool"]

    if tool == "semgrep":
        code_context = read_code_context(finding["filepath"], finding["line"])
        return f"""You are an AppSec engineer reviewing a Semgrep static analysis finding. Be concise and specific.

Finding
- Rule: `{finding["rule_id"]}`
- Description: {finding["rule_name"]}
- File: `{finding["filepath"]}:{finding["line"]}`
- Severity: {finding["severity"]}

Code context (→ marks the flagged line):
```
{code_context}
```

Respond with ONLY valid JSON, no markdown fences:
{{
  "is_tp": true or false,
  "one_liner": "one sentence: why this specific code is exploitable, or why it is a false positive",
  "fix": "unified diff with - and + lines showing the minimal change (null if false positive)",
  "fix_explanation": "one sentence on what the fix does (null if false positive)"
}}"""

    else:  # gitleaks or trivy
        code_context = read_code_context(finding["filepath"], finding["line"])
        match_info = f"\nMatched pattern: `{finding['extra']}`" if finding.get("extra") else ""
        return f"""You are an AppSec engineer reviewing a secret detected in source code. Be concise and specific.

Finding
- Tool: {tool.capitalize()}
- Rule: `{finding["rule_id"]}`
- Description: {finding["rule_name"]}
- File: `{finding["filepath"]}:{finding["line"]}`
- Severity: {finding["severity"]}{match_info}

Code context (→ marks the flagged line):
```
{code_context}
```

Respond with ONLY valid JSON, no markdown fences:
{{
  "is_tp": true or false,
  "one_liner": "one sentence: why this specific secret is dangerous, or why it is a false positive",
  "fix": "unified diff showing how to remove the hardcoded secret and replace with an environment variable (null if false positive)",
  "fix_explanation": "one sentence on what the fix does (null if false positive)"
}}"""


def analyze_finding(api_key: str, finding: dict) -> dict:
    prompt = build_prompt(finding)

    resp = requests.post(
        API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": MODEL,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()

    content = data["choices"][0]["message"]["content"]
    if not content:
        print(f"    [debug] full response: {data}")
        raise ValueError("Model returned empty content")

    text = content.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
    if text.endswith("```"):
        text = "\n".join(text.split("\n")[:-1])

    return json.loads(text.strip())


# ---------------------------------------------------------------------------
# PR comment
# ---------------------------------------------------------------------------

def build_comment(results: list[dict]) -> str:
    tps = [r for r in results if r["analysis"]["is_tp"]]
    fps = [r for r in results if not r["analysis"]["is_tp"]]

    sev_order = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3, "MEDIUM": 4, "LOW": 5, "INFO": 6}
    tps.sort(key=lambda r: (r["finding"]["tool"], sev_order.get(r["finding"]["severity"], 9)))

    tool_counts = {}
    for r in results:
        t = r["finding"]["tool"]
        tool_counts[t] = tool_counts.get(t, 0) + 1
    tools_summary = " · ".join(f"{v} {k}" for k, v in sorted(tool_counts.items()))

    lines = [
        COMMENT_MARKER,
        "## 🤖 AI Remediation Analysis",
        "",
        f"Analyzed **{len(results)} finding(s)** ({tools_summary}) · "
        f"{len(tps)} true positive(s) · {len(fps)} false positive(s)",
        "",
    ]

    if tps:
        tool_labels = {
            "semgrep": "🔍 Semgrep (SAST)",
            "gitleaks": "🔑 Gitleaks (Secrets)",
            "trivy": "📦 Trivy (SCA/Secrets)",
        }
        current_tool = None
        for r in tps:
            f = r["finding"]
            a = r["analysis"]
            if f["tool"] != current_tool:
                current_tool = f["tool"]
                lines += ["---", "", f"### {tool_labels.get(current_tool, current_tool)}", ""]
            emoji = {
                "CRITICAL": "🔴", "ERROR": "🔴", "HIGH": "🟠",
                "WARNING": "🟡", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪",
            }.get(f["severity"], "⚪")
            lines.append(f"**{emoji} [{f['severity']}] `{f['rule_id']}`**")
            lines.append(f"`{f['filepath']}:{f['line']}`")
            lines.append("")
            lines.append(a["one_liner"])
            lines.append("")
            if a.get("fix"):
                lines.append("<details>")
                lines.append("<summary><strong>Suggested fix</strong></summary>")
                lines.append("")
                lines.append("```diff")
                lines.append(a["fix"])
                lines.append("```")
                if a.get("fix_explanation"):
                    lines.append("")
                    lines.append(f"*{a['fix_explanation']}*")
                lines.append("")
                lines.append("</details>")
            lines.append("")

    if fps:
        lines += ["---", "", "### ✅ False positives", ""]
        for r in fps:
            f = r["finding"]
            a = r["analysis"]
            lines.append(f"- `{f['filepath']}:{f['line']}` — {a['one_liner']}")
        lines.append("")

    lines += [
        "---",
        f"*Generated by [{MODEL}](https://abliteration.ai) · "
        "[secure-pipeline-lab](https://github.com/Snozye/secure-pipeline-lab)*",
    ]
    return "\n".join(lines)


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
            print(f"Deleted previous AI comment {comment['id']}")


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
    findings = []
    findings += parse_semgrep(SARIF_PATH)
    findings += parse_gitleaks(GITLEAKS_PATH)
    findings += parse_trivy(TRIVY_PATH)

    if not findings:
        print("No findings to analyze.")
        sys.exit(0)

    tool_counts = {}
    for f in findings:
        tool_counts[f["tool"]] = tool_counts.get(f["tool"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(tool_counts.items()))
    print(f"Analyzing {len(findings)} finding(s) ({summary}) with {MODEL}...")

    api_key = os.environ["ABL_KEY"]

    results = []
    for f in findings:
        print(f"  [{f['tool']}] {f['rule_id']} @ {f['filepath']}:{f['line']}")
        try:
            analysis = analyze_finding(api_key, f)
        except Exception as exc:
            print(f"    ⚠ failed: {exc}")
            analysis = {
                "is_tp": True,
                "one_liner": "Analysis failed — review manually.",
                "fix": None,
                "fix_explanation": None,
            }
        results.append({"finding": f, "analysis": analysis})

    comment = build_comment(results)

    if os.environ.get("PR_NUMBER"):
        post_pr_comment(comment)
    else:
        print("\n--- COMMENT PREVIEW ---\n")
        print(comment)


if __name__ == "__main__":
    main()
