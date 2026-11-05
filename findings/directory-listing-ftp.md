# Finding: Directory Listing — /ftp

| Field | Value |
|-------|-------|
| **File** | `server.ts` |
| **Line** | 290 |
| **Rule** | `javascript.express.security.audit.express-serve-index-without-filter.express-serve-index-without-filter` |
| **Severity** | MEDIUM |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing |

## Vulnerable code

```typescript
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
```

## Why it's a finding

The `/ftp` endpoint renders a browsable directory listing and serves all files in the `ftp/` directory. This is the most impactful directory listing in Juice Shop — the `ftp/` directory contains:

- `acquisitions.md` — confidential M&A documents
- `www-data.bak` — potential backup with credentials
- `eastere.gg` — easter egg / challenge files
- Other sensitive documents intentionally placed for challenges

An unauthenticated attacker can browse to `/ftp`, enumerate all files, and download any of them.

## Impact

Direct information disclosure of confidential documents with no authentication required.

## Fix

Require authentication before serving `/ftp` contents. At minimum, disable directory listing and serve files only by exact name with explicit authorization checks.
