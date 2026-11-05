#!/usr/bin/env python3
"""
AI Remediation Advisor
Analyzes findings from one security tool (Semgrep, Gitleaks, or Trivy)
and posts a remediation comment on the PR.

Set TOOL=semgrep|gitleaks|trivy. Defaults to running all three (local testing).
"""

import json
import os
import sys
import time
import requests

SARIF_PATH = "semgrep-findings.sarif"
GITLEAKS_PATH = "gitleaks-report.json"
TRIVY_PATH = "trivy-findings.json"

CONTEXT_LINES = 8

PROVIDERS = [
    {
        "name": "abliteration",
        "model": "abliterated-model",
        "url": "https://api.abliteration.ai/v1/chat/completions",
        "key_env": "ABL_KEY",
        "max_tokens": 4096,
        "auth_header": "Authorization",  # value will be "Bearer {key}"
    },
    {
        "name": "gemini",
        "model": "gemini-3.8-flash",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "key_env": "GEMINI_KEY",
        "max_tokens": 4096,
        "auth_header": "Authorization",
    },
    {
        "name": "openrouter",
        "model": "google/gemma-2-9b-it:free",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_KEY",
        "max_tokens": 4096,
        "auth_header": "Authorization",
    },
]

TOOL = os.environ.get("TOOL", "all")
COMMENT_MARKER = f"<!-- ai-remediation-{TOOL} -->"


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
        # skip scan artifacts (e.g. semgrep-findings.sarif picked up by trivy)
        if target.endswith(".sarif") or target.endswith(".json"):
            continue
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
# AI analysis (batch — all findings in one API call)
# ---------------------------------------------------------------------------

def build_batch_prompt(findings: list[dict]) -> str:
    sections = []
    for i, f in enumerate(findings):
        code_context = read_code_context(f["filepath"], f["line"])
        match_info = f"\n  Matched: `{f['extra']}`" if f.get("extra") else ""
        sections.append(
            f"Finding {i + 1} [{f['tool']}]\n"
            f"- Rule: `{f['rule_id']}`\n"
            f"- Description: {f['rule_name']}\n"
            f"- File: `{f['filepath']}:{f['line']}`\n"
            f"- Severity: {f['severity']}{match_info}\n\n"
            f"Code context (→ marks flagged line):\n```\n{code_context}\n```"
        )

    body = "\n\n---\n\n".join(sections)
    return f"""You are an AppSec engineer reviewing security findings. Be concise and specific.

{body}

Respond with ONLY a valid JSON array (no markdown fences, no extra text), one object per finding in the same order:
[
  {{
    "is_tp": true or false,
    "one_liner": "one sentence: why exploitable or why false positive",
    "fix": "unified diff (- removed / + added lines) if is_tp=true, else null",
    "fix_explanation": "one sentence on what the fix does if is_tp=true, else null"
  }}
]"""


RETRY_DELAYS = {429: 60, 503: 30}
MAX_RETRIES = 2


def _call_provider(provider: dict, findings: list[dict]) -> list[dict]:
    key_env = provider["key_env"]
    api_key = os.environ.get(key_env, "")
    if not api_key:
        raise ValueError(f"No API key for provider {provider['name']} (env: {key_env})")

    auth_header = provider.get("auth_header", "Authorization")
    auth_value = f"Bearer {api_key}"

    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.post(
            provider["url"],
            headers={auth_header: auth_value, "Content-Type": "application/json"},
            json={
                "model": provider["model"],
                "max_tokens": provider["max_tokens"],
                "messages": [{"role": "user", "content": build_batch_prompt(findings)}],
            },
            timeout=120,
        )
        if resp.status_code in RETRY_DELAYS and attempt < MAX_RETRIES:
            delay = RETRY_DELAYS[resp.status_code]
            print(f"  [{provider['name']}] HTTP {resp.status_code} — retrying in {delay}s (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(delay)
            continue
        resp.raise_for_status()
        break

    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    if not content:
        print(f"  [debug] full response from {provider['name']}: {data}")
        raise ValueError(f"Provider {provider['name']} returned empty content")

    text = content.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
    if text.endswith("```"):
        text = "\n".join(text.split("\n")[:-1])

    result = json.loads(text.strip())
    if not isinstance(result, list):
        raise ValueError(f"Expected JSON array, got {type(result).__name__}")
    if len(result) != len(findings):
        raise ValueError(f"Expected {len(findings)} results, got {len(result)}")
    return result


def analyze_findings_batch(findings: list[dict]) -> tuple[list[dict], str]:
    """Send all findings in one API call. Returns (analyses, provider_name)."""
    last_exc: Exception = RuntimeError("No providers configured")
    for provider in PROVIDERS:
        try:
            results = _call_provider(provider, findings)
            return results, provider["name"]
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            body = exc.response.text[:300] if exc.response is not None else ""
            print(f"  [{provider['name']}] HTTP {status} — {body} — trying next provider")
            last_exc = exc
            if status not in (400, 402, 429, 500, 502, 503):
                break
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"  [{provider['name']}] {exc} — trying next provider")
            last_exc = exc
        except Exception as exc:
            print(f"  [{provider['name']}] unexpected error: {exc} — trying next provider")
            last_exc = exc
    raise last_exc


# ---------------------------------------------------------------------------
# PR comment
# ---------------------------------------------------------------------------

TOOL_LABELS = {
    "semgrep": "🔍 Semgrep (SAST)",
    "gitleaks": "🔑 Gitleaks (Secrets)",
    "trivy": "📦 Trivy (Secrets)",
}

SEV_EMOJI = {
    "CRITICAL": "🔴", "ERROR": "🔴", "HIGH": "🟠",
    "WARNING": "🟡", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪",
}

SEV_ORDER = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3, "MEDIUM": 4, "LOW": 5, "INFO": 6}


def build_comment(results: list[dict], tool_name: str) -> str:
    tps = [r for r in results if r["analysis"]["is_tp"]]
    fps = [r for r in results if not r["analysis"]["is_tp"]]
    tps.sort(key=lambda r: SEV_ORDER.get(r["finding"]["severity"], 9))

    label = TOOL_LABELS.get(tool_name, tool_name)
    lines = [
        COMMENT_MARKER,
        f"## {label} — AI Remediation",
        "",
        f"Analyzed **{len(results)} finding(s)** · {len(tps)} true positive(s) · {len(fps)} false positive(s)",
        "",
    ]

    if tps:
        lines.append("---")
        lines.append("")
        for r in tps:
            f = r["finding"]
            a = r["analysis"]
            emoji = SEV_EMOJI.get(f["severity"], "⚪")
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
        "*Generated by AI remediation advisor · "
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
    parsers = {
        "semgrep": lambda: parse_semgrep(SARIF_PATH),
        "gitleaks": lambda: parse_gitleaks(GITLEAKS_PATH),
        "trivy": lambda: parse_trivy(TRIVY_PATH),
    }

    if TOOL == "all":
        findings = []
        for parse in parsers.values():
            findings += parse()
        tool_name = "all"
    elif TOOL in parsers:
        findings = parsers[TOOL]()
        tool_name = TOOL
    else:
        print(f"Unknown TOOL={TOOL}. Use semgrep, gitleaks, trivy, or all.")
        sys.exit(1)

    if not findings:
        print(f"No findings for {TOOL}.")
        sys.exit(0)

    provider_names = [p["name"] for p in PROVIDERS if os.environ.get(p["key_env"])]
    print(f"Analyzing {len(findings)} finding(s) [{TOOL}] in one batch — providers: {', '.join(provider_names) or 'none configured'}")
    for f in findings:
        print(f"  [{f['tool']}] {f['rule_id']} @ {f['filepath']}:{f['line']}")

    try:
        analyses, used_provider = analyze_findings_batch(findings)
        print(f"✓ batch analyzed via {used_provider}")
    except Exception as exc:
        print(f"⚠ all providers failed: {exc}")
        analyses = [
            {"is_tp": True, "one_liner": "Analysis failed — review manually.", "fix": None, "fix_explanation": None}
            for _ in findings
        ]

    results = [{"finding": f, "analysis": a} for f, a in zip(findings, analyses)]

    comment = build_comment(results, tool_name)

    if os.environ.get("PR_NUMBER"):
        post_pr_comment(comment)
    else:
        print("\n--- COMMENT PREVIEW ---\n")
        print(comment)


if __name__ == "__main__":
    main()
