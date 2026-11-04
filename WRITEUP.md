# Building a DevSecOps Pipeline From Scratch: What the Tools Actually Found

I lost my job because a company replaced their AppSec screening process with automated tooling. I figured the best response was to learn how that tooling works from the inside.

This is a writeup of `secure-pipeline-lab` — a GitHub Actions pipeline I built on top of OWASP Juice Shop, an intentionally vulnerable Node.js app maintained for security training. The pipeline runs four security tools on every push: Semgrep (SAST), Trivy (SCA + secrets), Gitleaks (secrets), and OWASP ZAP (DAST). The build breaks on any finding not explicitly acknowledged.

What I want to document here isn't the pipeline setup itself — that's straightforward. What's interesting is what the tools actually found, where they disagreed, and what I had to fix to make the signal usable.

---

## The false positive problem

The first run of Semgrep returned 44 findings. After spending time with each one, 30 of them were false positives — a 68% FP rate.

The FPs weren't random noise. They came from two specific sources: workflow files in `.github/` matching injection rules that only make sense for application code, and test files matching patterns that are only dangerous in production. Neither is a real vulnerability. Both were firing because the rules don't know about context.

The fix is `.semgrepignore` — tell Semgrep which paths to skip. After that, 14 findings remain, all true positives, all with documented source-to-sink traces. FP rate: 0%.

This is the actual work of AppSec. Running a scanner is not hard. Knowing which 30 of 44 findings are noise, and being able to defend that decision to a team, is the skill.

---

## The finding I didn't expect from Trivy

Trivy is usually deployed as an SCA tool — it scans your dependencies for known CVEs. With `ignore-unfixed: true` (filter out vulnerabilities with no patch available), it found zero CVEs worth acting on.

What it did find: two hardcoded RSA private keys. One in `lib/insecurity.ts` (the JWT signing key), one in `terraform/networking.tf` (IaC secrets). I had Semgrep configured and running — Semgrep found the JWT key. It did not find the Terraform one. Different tools, different coverage areas.

This matters because IaC is often treated as infrastructure-only and left out of the SAST scope. Trivy scanned it without any configuration change. The terraform finding was there for free.

---

## The Gitleaks hole I found by accident

I wanted to verify that the secrets scanner was actually working, so I added a test secret to `server.ts`:

```typescript
const mySuperSecretPassword = 'ThisIsMySuperSecretAndSuperLongPassword!@#@ˆ!@231570159124'
```

Gitleaks didn't catch it.

Two reasons. First, the default Gitleaks ruleset is format-based — it matches known secret patterns like AWS access keys, GitHub tokens, and RSA keys. A generic variable named `mySuperSecretPassword` with an arbitrary string value doesn't match any of those patterns. Second, the action was configured to scan only the last commit diff by default.

The fix for the first problem: a custom rule in `.gitleaks.toml` targeting password-style variable assignments:

```toml
[[rules]]
id = "generic-password-variable"
regex = '''(?i)(?:password|passwd|secret|pwd)\s*(?:=|:)\s*['"][^'"]{8,}['"]'''
```

The fix for the second problem led to a more interesting discovery.

---

## The shallow clone problem

After switching to a filesystem scan to catch all secrets regardless of when they were introduced, the pipeline returned 309 findings. All of them on a single run.

The root cause: `actions/checkout@v4` defaults to `fetch-depth: 1`, which creates a shallow clone with exactly one commit. Gitleaks sees that commit as "all files introduced at once" — a diff against the empty tree — and scans the entire 14MB codebase as a single commit's diff.

On a deliberately vulnerable application like Juice Shop, 309 findings is what you get. Every hardcoded secret, every RSA key, every password in the test fixtures, all appearing as "introduced in this commit."

The fix is `fetch-depth: 0` (full history) combined with `--log-opts="-1"` (scan only the actual diff of the most recent commit). This gives you the right behavior: the scanner sees the real diff, not an artifact of how the checkout was configured.

After the fix: 0 findings on clean commits, 2 findings when the test secret is present.

---

## What DAST found that SAST missed

OWASP ZAP baseline scan crawled 116 URLs and returned 7 findings. After classification: 5 true positives, 2 false positives (28.6% FP rate).

The FPs were "Storable and Cacheable Content" (static assets are supposed to be cached) and "Modern Web Application" (ZAP noting it detected a SPA, not a vulnerability).

The interesting TPs: missing CSP header, overpermissive CORS (`Access-Control-Allow-Origin: *`), missing COEP header. None of these are findable by SAST — they're runtime HTTP response headers, not code patterns.

One finding overlapped with what Semgrep had already found: ZAP flagged dangerous JS functions in the compiled Angular bundle. That corresponds to the `eval()` call in `routes/userProfile.ts:65` that Semgrep found in the source code. Two scanners, completely different methods, same code path. That kind of independent confirmation carries weight in a triage meeting.

What ZAP didn't find: SQL injection, path traversal, the hardcoded JWT key. The baseline scan is passive — it doesn't send attack payloads, it only observes traffic. Active scan would catch SQLi, but that's a different risk profile to run in CI.

---

## The suppression question

After tuning ZAP's output with a `zap.rules` suppression file, the pipeline stopped reporting the 5 known Juice Shop vulnerabilities. Someone asked me: doesn't that mean you're hiding real vulnerabilities?

The right way to think about suppression in CI: you're not hiding vulnerabilities, you're documenting known ones so the pipeline can catch new ones. If ZAP reports 7 findings on every run, your team stops reading the output. The signal is gone. The value of a CI security gate is that it reliably catches regressions — findings that weren't there before.

In a real project, suppression requires a linked ticket, a deadline, and a named owner. The intent is "we know about this, here's the remediation plan" — not "ignore this forever."

---

## Cross-tool coverage map

| Vulnerability | Semgrep | Trivy | Gitleaks | ZAP |
|---------------|---------|-------|----------|-----|
| SQLi (search endpoint) | ✅ | — | — | ❌ (passive) |
| RCE via eval() | ✅ | — | — | ✅ (compiled bundle) |
| Hardcoded JWT key | ✅ | ✅ | — | — |
| Hardcoded IaC key | ❌ | ✅ | — | — |
| Generic password in code | — | — | ✅ | — |
| Missing CSP/CORS/COEP | ❌ | — | — | ✅ |

No single tool covers everything. The pipeline needs all four.

---

## Final FP rates

| Tool | Findings | FP rate after tuning |
|------|----------|----------------------|
| Semgrep | 14 | 0% |
| Trivy | 2 | 0% |
| Gitleaks | 0 (clean commits) | — |
| ZAP | 7 | 28.6% |

ZAP's FP rate is the highest by a significant margin. This is typical for DAST tools — they observe runtime behavior without semantic context, so they flag caching behavior and framework detection alongside real issues. The classification work is unavoidable.

---

## Repository

The full pipeline, suppression configs, and per-finding analysis are at [joaovbvs/juice-shop](https://github.com/joaovbvs/juice-shop). The findings directory has individual files for each vulnerability with source-to-sink traces where applicable.
