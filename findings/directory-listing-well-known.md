# Finding: Directory Listing — /.well-known

| Field | Value |
|-------|-------|
| **File** | `server.ts` |
| **Line** | 294 |
| **Rule** | `javascript.express.security.audit.express-serve-index-without-filter.express-serve-index-without-filter` |
| **Severity** | MEDIUM |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing |

## Vulnerable code

```typescript
app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
app.use('/.well-known', express.static('.well-known'))
```

## Why it's a finding

`/.well-known/` is an IETF-standardized path (RFC 8615) for hosting metadata files. Enabling directory listing here exposes the full set of files stored under `.well-known/`. Depending on what is stored (security.txt, change-password endpoints, ACME challenge tokens), listing this directory can aid an attacker in mapping the application's security configuration and trust relationships.

## Impact

Lower severity than `/ftp` or `/encryptionkeys`, but still unnecessary information disclosure.

## Fix

Disable directory listing while keeping `express.static` to allow direct access to known files:

```typescript
// Remove serveIndex — keep only static file serving
app.use('/.well-known', express.static('.well-known'))
```
