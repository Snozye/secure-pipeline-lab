# Finding: Open Redirect

| Field | Value |
|-------|-------|
| **File** | `routes/redirect.ts` |
| **Line** | 18 |
| **Rule** | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| **Severity** | MEDIUM |
| **CWE** | CWE-601: URL Redirection to Untrusted Site |

## Vulnerable code

```typescript
const toUrl: string = query.to as string
if (security.isRedirectAllowed(toUrl)) {
  challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
  res.redirect(toUrl)
} else {
  res.status(406)
  next(new Error('Unrecognized target URL for redirect: ' + toUrl))
}
```

## Source → Sink

**Source**: `query.to` (URL query parameter — attacker-controlled)  
**Sink**: `res.redirect(toUrl)` — HTTP 302 redirect to attacker-controlled URL

## Why it's exploitable

`isRedirectAllowed()` checks the URL against an allowlist of trusted domains. However, `isUnintendedRedirect()` demonstrates that the check can be bypassed (this is by design as a Juice Shop challenge). The allowlist logic uses `startsWith()` which can be bypassed using URLs like `https://allowedhost.com.evil.com/`.

An open redirect is used in phishing: an attacker sends a link like `https://juice-shop.example.com/redirect?to=https://evil.com` which appears legitimate but redirects victims to a malicious site.

## Proof of concept

```
GET /redirect?to=https://github.com (allowed)
GET /redirect?to=https://evil.com   (blocked — 406)
```

Bypass (if allowlist uses loose matching):
```
GET /redirect?to=https://github.com.evil.com/
```

## Fix

Validate against a strict allowlist of full URLs or use an internal redirect token map instead of accepting arbitrary URLs:

```typescript
const allowedRedirects: Record<string, string> = {
  'github': 'https://github.com/juice-shop/juice-shop'
}
const destination = allowedRedirects[query.to as string]
if (!destination) return res.status(406).end()
res.redirect(destination)
```
