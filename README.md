# OWASP Juice Shop — Manual Code Review & Semgrep Rule Authoring

> **Study project — AppSec portfolio.**  
> This repository is a fork of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) used as a target for manual source-code security review. The goal is **not** to run a scanner and check boxes — it is to read the Node.js/Express source, trace data flows by hand, and then author Semgrep rules that reliably catch each pattern in CI.

---

## Objective

| Goal | Deliverable |
|------|-------------|
| Map 10+ vulnerabilities without a scanner | [`findings/`](findings/) — one markdown file per finding: file, line, source, sink, fix |
| Author one Semgrep rule per pattern found | [`semgrep-rules/`](semgrep-rules/) — YAML rules, each matching the exact sink |
| Validate rules against the live codebase | `semgrep scan --config semgrep-rules/ .` must flag every finding |
| Tune false-positive rate to < 10% | [`findings/fp-analysis.md`](findings/fp-analysis.md) — tuning log |

This is the artifact that goes in `github.com/Snozye/code-review-notes` and that justifies the "code review" and "SAST" lines on the CV.

---

## Methodology

Manual review before any tool. For each vulnerability:

1. **Identify the source** — where user-controlled input enters the application (HTTP parameter, header, body field, file upload, cookie).
2. **Trace the sink** — follow the data through middleware, service layers and ORM calls to where it lands: SQL query, shell command, file path, HTML response, `eval()`, deserialization.
3. **Confirm exploitability** — verify that no sanitization, parameterization or encoding sits between source and sink.
4. **Write the fix** — minimal, idiomatic change: parameterized query, escaped output, schema validation, etc.
5. **Write the rule** — Semgrep YAML that matches the exact pattern, not just the keyword.

Only after steps 1–5 is a finding complete.

---

## Findings Index

| # | Vulnerability | File | Line | OWASP | Severity |
|---|---------------|------|------|-------|----------|
| 01 | SQL Injection via raw string concatenation | `routes/searchProducts.ts` | — | A03 | Critical |
| 02 | Reflected XSS — user-controlled value in HTTP response without encoding | `routes/userProfile.ts` | — | A03 | High |
| 03 | Broken Object-Level Authorization (IDOR) on basket endpoint | `routes/basket.ts` | — | API1 | High |
| 04 | JWT `alg: none` acceptance — signature verification bypassed | `lib/insecurity.ts` | — | A02 | Critical |
| 05 | Path traversal on file download route | `routes/fileServer.ts` | — | A05 | High |
| 06 | Insecure deserialization via `eval()` on B2B order endpoint | `routes/b2bOrder.ts` | — | A08 | Critical |
| 07 | Missing rate-limiting on login — credential stuffing | `routes/login.ts` | — | A07 | Medium |
| 08 | Sensitive data exposure — full user object returned via REST | `routes/currentUser.ts` | — | A02 | Medium |
| 09 | SSRF on request-forwarding endpoint | `routes/chat.ts` | — | A10 | High |
| 10 | Prototype pollution via `merge()` on user-supplied object | `lib/utils.ts` | — | A03 | High |

> Each row links to a full finding in [`findings/`](findings/), with source→sink trace, PoC payload, and fix.

---

## Semgrep Rules

Rules live in [`semgrep-rules/`](semgrep-rules/). Each rule:

- matches the **pattern**, not just the function name
- includes a **test case** (`# ruleid:` and `# ok:` comments in the target file)
- documents the **false-positive rate** after running against the full codebase

### Run

```bash
# Install
pip install semgrep

# Scan with custom rules
semgrep scan --config semgrep-rules/ --metrics=off .

# Scan with Semgrep registry (baseline comparison)
semgrep scan --config p/owasp-top-ten --metrics=off .
```

### Rules authored

| Rule ID | Pattern | Findings caught |
|---------|---------|-----------------|
| `sqli-string-concat` | String concatenation passed to Sequelize raw query | F01 |
| `jwt-alg-none` | `verify()` called without `algorithms` whitelist | F04 |
| `path-traversal-join` | `path.join()` with unsanitized user input | F05 |
| `eval-user-input` | `eval()` receiving HTTP body field | F06 |
| `proto-pollution-merge` | Deep merge of user-supplied object into application state | F10 |

---

## False-Positive Analysis

Running `semgrep-rules/` against the full Juice Shop codebase:

| Rule | True Positives | False Positives | FP Rate | Tuning applied |
|------|---------------|-----------------|---------|----------------|
| `sqli-string-concat` | — | — | — | — |
| `jwt-alg-none` | — | — | — | — |
| `path-traversal-join` | — | — | — | — |

> This table is updated as findings and rules are completed. Target: FP rate < 10% across all rules before the rules are considered portfolio-ready.

---

## Repo Layout

```
.
├── findings/
│   ├── 01-sqli-search-products.md
│   ├── 02-xss-user-profile.md
│   ├── ...
│   └── fp-analysis.md
├── semgrep-rules/
│   ├── sqli-string-concat.yaml
│   ├── jwt-alg-none.yaml
│   └── ...
└── README.md          ← this file
```

The Juice Shop source itself is not modified. All vulnerability documentation references the original files and line numbers.

---

## Why this matters for AppSec

The gap this project closes: being able to **read code that was written by someone else, in a language I did not write in production, and find the vulnerability without a tool telling me where to look**.

The scanner comes after — to prove the pattern is real, to write the rule, and to make sure it fires in CI before the code ships. That is the cycle: manual review → rule authoring → pipeline integration (see [secure-pipeline-lab](https://github.com/Snozye/secure-pipeline-lab)).

---

## Status

- [x] Methodology defined
- [x] Repository set up
- [ ] Findings 01–10 documented
- [ ] Semgrep rules authored and tested
- [ ] False-positive tuning complete
- [ ] Pipeline integration validated

---

## Target application

OWASP Juice Shop is maintained at [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop).  
License: [MIT](LICENSE)

