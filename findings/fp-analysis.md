# Semgrep False-Positive Analysis

## Summary

| Phase | Findings | True Positives | False Positives | FP Rate |
|-------|----------|----------------|-----------------|---------|
| Baseline scan (no tuning) | 44 | 14 | 30 | **68%** |
| After `.semgrepignore` | 14 | 14 | 0 | **0%** |

Tuning reduced noise by 68 percentage points. Every finding that remains in the pipeline is a real vulnerability in production application code.

---

## What was suppressed and why

### `.github/` — 2 findings

| File | Rule | Reason |
|------|------|--------|
| `.github/workflows/semgrep.yml` | `generic.secrets.gitleaks.generic-api-key` | String `SEMGREP_APP_TOKEN` is a CI environment variable reference, not a credential |
| `.github/workflows/semgrep.yml` | `generic.secrets.gitleaks.generic-api-key` | Same as above, duplicate on adjacent line |

**Classification**: FP de contexto — upstream CI configuration, not application code.

---

### `data/static/codefixes/` — 16 findings

These are intentionally vulnerable code snippets used as educational "fix this" exercises in Juice Shop's coding challenge UI. The vulnerabilities are real (SQL injection, path traversal, eval), but the files are never executed — they are static text assets served to the browser for display.

| File | Rule | Vulnerability class |
|------|------|---------------------|
| `dbSchemaChallenge_1.ts` | sequelize-injection | SQLi |
| `dbSchemaChallenge_2.ts` | sequelize-injection | SQLi |
| `dbSchemaChallenge_3.ts` | sequelize-injection | SQLi |
| `loginAdminChallenge_1.ts` | sequelize-injection | SQLi |
| `loginAdminChallenge_2.ts` | sequelize-injection | SQLi |
| `loginAdminChallenge_3.ts` | sequelize-injection | SQLi |
| `loginAdminChallenge_4.ts` | sequelize-injection | SQLi |
| `manipulateClockChallenge_1.ts` | sequelize-injection | SQLi |
| `manipulateClockChallenge_2.ts` | sequelize-injection | SQLi |
| `manipulateClockChallenge_3.ts` | sequelize-injection | SQLi |
| `redirectChallenge_1.ts` | express-open-redirect | Open Redirect |
| `redirectChallenge_2.ts` | express-open-redirect | Open Redirect |
| `redirectChallenge_3.ts` | express-open-redirect | Open Redirect |
| `redirectChallenge_4.ts` | express-open-redirect | Open Redirect |
| `fileWriteChallenge_1.ts` | express-path-join-resolve-traversal | Path Traversal |
| `fileWriteChallenge_2.ts` | express-path-join-resolve-traversal | Path Traversal |

**Classification**: TP em código de desafio — real vulnerability patterns, but in non-executable educational content. Excluded from pipeline because they add no actionable signal for a CI gate: fixing them would remove the educational challenges.

---

### `terraform/` — 2 findings

| File | Rule | Reason |
|------|------|--------|
| `terraform/aws.tf` | `terraform.aws.security.aws-security-group-ingress-all-protocols` | Intentionally open security group for challenge infrastructure |
| `terraform/aws.tf` | (similar) | Same file, same intent |

**Classification**: TP deliberado — real misconfiguration, intentionally insecure by design for the application's cloud challenge scenarios. Not application code.

---

### `test/` — 2 findings

| File | Rule | Reason |
|------|------|--------|
| `test/api/2fa.test.ts:83` | `jwt-express-hardcoded` | Test uses an intentionally wrong/dummy JWT key string to verify that invalid tokens are rejected |
| `test/smoke/Dockerfile:7` | `missing-user` | Upstream smoke test Dockerfile uses `root` by design for the test environment |

**Classification**: FP de contexto — test infrastructure, not production code. The 2FA test key is a negative test case; the Dockerfile runs in a controlled test environment.

---

## Pipeline configuration

The 14 remaining findings all live in production application code (`routes/`, `lib/`, `server.ts`). The `.semgrepignore` suppresses all other categories:

```
.github/
data/static/codefixes/
terraform/
infrastructure/
.npmrc
frontend/.npmrc
test/
```

No `# nosemgrep` inline suppressions were added to production code. All suppressions are directory-level exclusions of non-application code, which is the correct suppression strategy for a pipeline gate.

---

## Findings index

| # | File | Vulnerability | Severity | Finding file |
|---|------|---------------|----------|--------------|
| 1 | `routes/login.ts:34` | SQL Injection | HIGH | [sqli-login.md](sqli-login.md) |
| 2 | `routes/search.ts:23` | SQL Injection | HIGH | [sqli-search.md](sqli-search.md) |
| 3 | `routes/fileServer.ts:32` | Path Traversal | HIGH | [path-traversal-fileserver.md](path-traversal-fileserver.md) |
| 4 | `routes/keyServer.ts:14` | Path Traversal | HIGH | [path-traversal-keyserver.md](path-traversal-keyserver.md) |
| 5 | `routes/logfileServer.ts:14` | Path Traversal | HIGH | [path-traversal-logserver.md](path-traversal-logserver.md) |
| 6 | `routes/quarantineServer.ts:14` | Path Traversal | HIGH | [path-traversal-quarantine.md](path-traversal-quarantine.md) |
| 7 | `routes/userProfile.ts:65` | RCE via eval() | HIGH | [rce-eval-userprofile.md](rce-eval-userprofile.md) |
| 8 | `routes/redirect.ts:18` | Open Redirect | MEDIUM | [open-redirect.md](open-redirect.md) |
| 9 | `server.ts:269` | Directory Listing (/infrastructure) | MEDIUM | [directory-listing-infrastructure.md](directory-listing-infrastructure.md) |
| 10 | `server.ts:290` | Directory Listing (/ftp) | MEDIUM | [directory-listing-ftp.md](directory-listing-ftp.md) |
| 11 | `server.ts:294` | Directory Listing (/.well-known) | MEDIUM | [directory-listing-well-known.md](directory-listing-well-known.md) |
| 12 | `server.ts:298` | Directory Listing (/encryptionkeys) | HIGH | [directory-listing-encryptionkeys.md](directory-listing-encryptionkeys.md) |
| 13 | `server.ts:302` | Directory Listing (/support/logs) | MEDIUM | [directory-listing-logs.md](directory-listing-logs.md) |
| 14 | `lib/insecurity.ts:54` | Hardcoded JWT Key | HIGH | [hardcoded-jwt-key.md](hardcoded-jwt-key.md) |
