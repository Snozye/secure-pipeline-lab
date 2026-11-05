# secure-pipeline-lab

A DevSecOps pipeline built on top of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — an intentionally vulnerable Node.js application used as the scan target.

> **Authorship note:** This repo vendors OWASP Juice Shop as the scan target. My work is in
> `.github/workflows/`, `scripts/`, `findings/`, `WRITEUP.md`, and the tuning configs
> (`.semgrepignore`, `.gitleaks.toml`, `zap.rules`). Everything else is upstream Juice Shop,
> included so the pipeline has a real target to scan.

The pipeline runs four security tools on every push. The interesting work is not running the tools — it's what comes after: classifying hundreds of findings, tuning each tool until the signal-to-noise ratio is usable, and documenting every decision.

---

## Pipeline

| Tool | Category | Findings | FP rate before tuning | FP rate after tuning |
|------|----------|----------|-----------------------|----------------------|
| [Semgrep](https://semgrep.dev) | SAST | 44 → 14 | 68% | 0% |
| [Trivy](https://trivy.dev) | SCA + secrets | 2 | 0% | 0% |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | catches new commits | — | — |
| [OWASP ZAP](https://www.zaproxy.org) | DAST | 7 (5 TP, 2 FP) | — | 28.6% |

The build breaks on any unacknowledged finding.

---

## What the tools found

### SQL Injection — confirmed in runtime

Semgrep flagged `routes/search.ts:23` for raw Sequelize query interpolation. Confirmed by running the full UNION-based attack chain against the running application:

```
GET /rest/products/search?q=')) UNION SELECT email,password,role,4,5,6,7,8,9,10 FROM Users--
```

Returns all user credentials. The length check (`criteria.length <= 200`) is not a security control — injection payloads are typically under 200 characters.

### RCE via eval() — found by SAST and DAST independently

Semgrep found `eval()` in `routes/userProfile.ts:65`. OWASP ZAP independently flagged dangerous JS functions in the compiled frontend bundle. Two scanners, different methods, same code path.

Attack chain: `PUT /rest/users/me` with username `#{require('child_process').execSync('id').toString()}` → `GET /profile` → arbitrary command execution.

### Hardcoded RSA private key — found by both Semgrep and Trivy

The JWT signing key in `lib/insecurity.ts:21` is hardcoded and publicly readable. An attacker with access to the repository can forge tokens for any user including admins. Trivy also found a second RSA key in `terraform/networking.tf` (IaC secrets) — a category Semgrep's community rules do not cover.

### Path traversal — TP with reduced exploitability

Four file server routes contain path traversal patterns. The interesting finding: Express normalizes `..%2F` before the handler sees it, blocking direct traversal in runtime testing. The exploitable vector is the null byte technique (`%2500`) in the file server, which passes the allowlist check then gets stripped by `cutOffPoisonNullByte()`.

---

## Tuning decisions

### Semgrep: 44 → 14 findings (68% FP → 0%)

The 30 FPs came from two categories:
- `.github/` workflow files matching injection rules out of context
- `test/` files matching patterns that are only dangerous in production code

Suppressed via `.semgrepignore`. The 14 remaining findings are all true positives with documented source→sink traces.

### Gitleaks: custom rule added

Default Gitleaks rules match known secret formats (AWS keys, GitHub tokens, RSA keys). A generic `const mySuperSecretPassword = '...'` does not match any default pattern. Added a custom rule in `.gitleaks.toml` targeting password-style variable assignments.

Also discovered: `actions/checkout@v4` with default `fetch-depth: 1` creates a shallow clone. Gitleaks treats the single fetched commit as "all files introduced at once" and scans the entire codebase — producing 309 findings on a deliberately vulnerable app. Fix: `fetch-depth: 0` + `--log-opts="-1"` to scan only the actual diff of the latest commit.

### ZAP: 7 findings, 2 FPs

FPs: "Storable and Cacheable Content" (static assets are supposed to be cached) and "Modern Web Application" (informational metadata, not a vulnerability).

The 5 TPs — missing CSP, overpermissive CORS, missing COEP, deprecated Feature-Policy, eval() in bundle — are suppressed via `zap.rules` because they are intentional Juice Shop vulnerabilities. In a real project, suppression would require a linked ticket, a deadline, and a named owner. The pipeline catches any *new* findings not in the suppression list.

---

## Findings

| Finding | File | Severity | Confirmed in runtime |
|---------|------|----------|----------------------|
| [SQL Injection — Login](findings/sqli-login.md) | `routes/login.ts:34` | HIGH | ✅ |
| [SQL Injection — Search](findings/sqli-search.md) | `routes/search.ts:23` | HIGH | ✅ |
| [RCE via eval()](findings/rce-eval-userprofile.md) | `routes/userProfile.ts:65` | CRITICAL | ✅ |
| [Hardcoded JWT key](findings/hardcoded-jwt-key.md) | `lib/insecurity.ts:21` | HIGH | — |
| [Path traversal — file server](findings/path-traversal-fileserver.md) | `routes/fileServer.ts:32` | HIGH | partial |
| [Path traversal — key server](findings/path-traversal-keyserver.md) | `routes/keyServer.ts:14` | HIGH | ❌ |
| [Path traversal — log server](findings/path-traversal-logserver.md) | `routes/logfileServer.ts:14` | HIGH | ❌ |
| [Path traversal — quarantine](findings/path-traversal-quarantine.md) | `routes/quarantineServer.ts:14` | HIGH | ❌ |
| [FP analysis — Semgrep](findings/fp-analysis.md) | — | — | — |
| [FP analysis — Trivy](findings/trivy-fp-analysis.md) | — | — | — |
| [FP analysis — Gitleaks](findings/gitleaks-analysis.md) | — | — | — |
| [FP analysis — ZAP](findings/zap-analysis.md) | — | — | — |

---

## Upstream

OWASP Juice Shop is maintained at [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop). License: [MIT](LICENSE)


## Pipeline Status

All scans run on every PR.
