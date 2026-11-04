#!/usr/bin/env python3
"""
AI Remediation Advisor
Reads Semgrep SARIF findings, calls Claude for each finding,
and posts a consolidated remediation comment on the PR.

Usage in CI: set ANTHROPIC_API_KEY, GITHUB_TOKEN, PR_NUMBER, REPO.
Usage locally: set only ANTHROPIC_API_KEY — prints comment to stdout.
"""

import json
import os
import sys
import requests
import anthropic

SARIF_PATH = "semgrep-findings.sarif"
CONTEXT_LINES = 8
COMMENT_MARKER = "<!-- ai-remediation-advisor -->"
MODEL = "claude-sonnet-5-5"


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


def analyze_finding(client: anthropic.Anthropic, finding: dict) -> dict:
    code_context = read_code_context(finding["filepath"], finding["line"])

    prompt = f"""You are an AppSec engineer reviewing a Semgrep finding. Be concise and specific.

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
  "fix": "unified diff with - and + lines showing the minimal change (null if false positive or no code change needed)",
  "fix_explanation": "one sentence on what the fix does (null if false positive)"
}}"""

    msg = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    text = msg.content[0].text.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
    if text.endswith("```"):
        text = "\n".join(text.split("\n")[:-1])

    return json.loads(text.strip())


def parse_sarif(path: str) -> list[dict]:
    with open(path) as f:
        sarif = json.load(f)

    seen = set()
    findings = []

    for run in sarif.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            rule_name = (
                rule.get("shortDescription", {}).get("text", "")
                or rule.get("name", rule_id)
            )
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

                findings.append(
                    {
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "filepath": uri,
                        "line": line,
                        "severity": severity,
                    }
                )

    return findings


def build_comment(results: list[dict]) -> str:
    tps = [r for r in results if r["analysis"]["is_tp"]]
    fps = [r for r in results if not r["analysis"]["is_tp"]]

    sev_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    tps.sort(key=lambda r: sev_order.get(r["finding"]["severity"], 9))

    lines = [
        COMMENT_MARKER,
        "## 🤖 AI Remediation Analysis",
        "",
        f"Analyzed **{len(results)} finding(s)** · "
        f"{len(tps)} true positive(s) · {len(fps)} false positive(s)",
        "",
    ]

    if tps:
        lines += ["---", ""]
        for r in tps:
            f = r["finding"]
            a = r["analysis"]
            emoji = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(
                f["severity"], "⚪"
            )
            lines.append(
                f"### {emoji} [{f['severity']}] `{f['rule_id']}`"
            )
            lines.append(f"`{f['filepath']}:{f['line']}`")
            lines.append("")
            lines.append(f"{a['one_liner']}")
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
        f"*Generated by [{MODEL}](https://anthropic.com) · "
        "[secure-pipeline-lab](https://github.com/Snozye/secure-pipeline-lab)*",
    ]

    return "\n".join(lines)


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


def main() -> None:
    if not os.path.exists(SARIF_PATH):
        print("No SARIF file found — skipping AI analysis.")
        sys.exit(0)

    findings = parse_sarif(SARIF_PATH)
    if not findings:
        print("No findings to analyze.")
        sys.exit(0)

    print(f"Analyzing {len(findings)} finding(s) with {MODEL}...")

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    results = []
    for f in findings:
        print(f"  {f['rule_id']} @ {f['filepath']}:{f['line']}")
        try:
            analysis = analyze_finding(client, f)
        except Exception as exc:
            print(f"    ⚠ analysis failed: {exc}")
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
