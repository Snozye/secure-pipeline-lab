# OWASP ZAP — False Positive Analysis

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 7 |
| True Positives | 5 |
| False Positives | 2 |
| **FP Rate** | **28.6%** |
| Scan type | Baseline (passive) |
| URLs crawled | 116 |

All findings suppressed via `zap.rules` — they are intentional Juice Shop vulnerabilities documented below.

---

## Finding Classification

### [10038] Content Security Policy (CSP) Header Not Set — **TP**

5 URLs affected, including the main application page.

The app does not set a `Content-Security-Policy` header. CSP is the primary defense against XSS — without it, any injected script runs with full page privileges. For Juice Shop this is intentional (the app has multiple XSS challenges).

Suppressed as known TP.

---

### [10049] Storable and Cacheable Content — **FP**

6 URLs: `robots.txt`, `favicon.ico`, JavaScript bundles, `sitemap.xml`.

These are static public assets. Being cached is correct and expected behavior. This rule becomes relevant when sensitive API responses lack `Cache-Control: no-store` — for static files it is a false positive.

Suppressed as FP.

---

### [10063] Deprecated Feature-Policy Header — **TP (low)**

The app sets `Feature-Policy`, which was deprecated in favor of `Permissions-Policy`. Technically a misconfiguration but purely cosmetic — both headers serve the same purpose and browsers still accept both.

Suppressed as low-severity noise.

---

### [10098] Cross-Domain Misconfiguration — **TP**

5 URLs respond with `Access-Control-Allow-Origin: *`. This overly permissive CORS policy allows any website to make credentialed cross-origin requests on behalf of a logged-in user. For Juice Shop this is intentional (REST API challenge).

Suppressed as known TP.

---

### [10109] Modern Web Application — **FP (informational)**

ZAP informing that it detected a Single Page Application (Angular). This is a scan metadata note, not a vulnerability — ZAP warns that some passive rules may not fire correctly on SPAs with JavaScript-rendered content.

Suppressed as informational / not a vulnerability.

---

### [10110] Dangerous JS Functions — **TP**

Found in `main.js` and `chunk-AkObRTpM.js` (compiled Angular bundle). This corresponds to the `eval()` call in `routes/userProfile.ts:65` documented in [`findings/rce-eval-userprofile.md`](rce-eval-userprofile.md). ZAP detected it in the compiled frontend bundle — confirming the same code path found by Semgrep SAST.

This is an example of SAST and DAST independently confirming the same vulnerability.

Suppressed as known TP (documented separately).

---

### [90004] Cross-Origin-Embedder-Policy Header Missing — **TP**

COEP header not set on 10 responses. COEP is required to enable `SharedArrayBuffer` and high-resolution timers, which are needed for Spectre-style cross-origin side-channel attacks. Missing COEP is a real security gap but low severity for most applications.

Suppressed as known TP.

---

## Comparison: SAST vs DAST coverage

| Vulnerability | Semgrep (SAST) | ZAP (DAST) |
|---------------|---------------|------------|
| eval() / RCE | ✅ Found in source | ✅ Found in bundle |
| SQLi | ✅ Found in source | ❌ Not detected (passive scan) |
| Path traversal | ✅ Found in source | ❌ Not detected (passive scan) |
| Hardcoded JWT key | ✅ Found in source | ❌ Not detected |
| Missing CSP | ❌ Not a SAST concern | ✅ Found at runtime |
| CORS misconfiguration | ❌ Not a SAST concern | ✅ Found at runtime |
| Missing COEP | ❌ Not a SAST concern | ✅ Found at runtime |

SAST catches logic and code-level flaws. DAST catches runtime behavior (missing headers, actual HTTP responses). Neither replaces the other — both are necessary.
