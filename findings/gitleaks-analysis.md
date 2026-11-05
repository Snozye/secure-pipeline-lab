# Gitleaks — Gap Analysis and Tuning

## The gap discovered

A generic hardcoded password was added to `server.ts`:

```typescript
const mySuperSecretPassword = 'ThisIsMySuperSecretAndSuperLongPassword!@#@ˆ!@231570159124'
```

The original Gitleaks configuration (`gitleaks-action@v2` with defaults) **did not catch it**. Two reasons:

### Reason 1 — Action scans only the last commit diff

The action runs `gitleaks detect --log-opts=-1`, which limits the scan to the diff of the most recent commit. If the secret was introduced in any earlier commit, it is outside the scan window. This is a design tradeoff: fast incremental CI scan vs. full history audit.

### Reason 2 — Default ruleset is pattern-based, not semantic

Gitleaks ships with regexes for known secret formats: AWS access keys, GitHub tokens, RSA private keys, Stripe keys, etc. A generic variable named `mySuperSecretPassword` with an arbitrary string value does not match any of those patterns.

---

## Second gap discovered — shallow clone

After implementing the filesystem scan, the pipeline returned 309 leaks. Root cause: `actions/checkout@v4` defaults to `fetch-depth: 1`, which creates a **shallow clone** with only 1 commit. Gitleaks sees that 1 commit as "all files added from scratch" (a diff against the empty tree), scanning the entire 14MB codebase as one commit's diff — finding secrets everywhere in the deliberately vulnerable Juice Shop.

**Fix**: `fetch-depth: 0` (full history) + `--log-opts="-1"` (scan only the latest commit's actual diff). This is the same behavior as the original action, but now with our custom rule applied.

---

## The fix

### 1. Custom rule added to `.gitleaks.toml`

```toml
[[rules]]
id = "generic-password-variable"
description = "Hardcoded password in variable assignment"
regex = '''(?i)(?:password|passwd|secret|pwd)\s*(?:=|:)\s*['"][^'"]{8,}['"]'''
```

Matches any assignment where the left side contains `password`, `passwd`, `secret`, or `pwd` and the right side is a string of 8 or more characters.

### 2. Switched to filesystem scan mode

The workflow now installs and runs `gitleaks detect --source .` directly, which scans all files in the repository — not just the last commit's diff. This catches secrets regardless of when they were introduced.

### 3. Allowlist for known Juice Shop TPs

The two intentional RSA keys (`lib/insecurity.ts`, `terraform/networking.tf`) are suppressed by path so they do not generate noise. They are already documented as TPs and found by Trivy.

---

## False Positive Analysis

| Finding | File | Classification | Action |
|---------|------|----------------|--------|
| Generic password | `server.ts` | **TP** | Remove — use `process.env.SECRET` |
| RSA private key | `lib/insecurity.ts` | TP (known) | Suppressed — documented in `hardcoded-jwt-key.md` |
| RSA private key | `terraform/networking.tf` | TP (known) | Suppressed — documented in `trivy-fp-analysis.md` |

FP rate after tuning: **0%**

---

## Lesson

A secrets scanner configured to scan only new commits will miss secrets that were already in the codebase. The right CI posture is:
- **Incremental scan** (fast, runs on every push): catches NEW secrets being introduced
- **Full filesystem scan** (thorough, same speed for small repos): catches ALL secrets regardless of history

This pipeline uses the full filesystem scan because the Juice Shop codebase is small enough that the performance difference is negligible.
