# Finding: Directory Listing — /support/logs

| Field | Value |
|-------|-------|
| **File** | `server.ts` |
| **Line** | 302 |
| **Rule** | `javascript.express.security.audit.express-serve-index-without-filter.express-serve-index-without-filter` |
| **Severity** | MEDIUM |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing |

## Vulnerable code

```typescript
app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' }))
app.use('/support/logs/:file', serveLogFiles())
```

## Why it's a finding

The `/support/logs` endpoint exposes the full application access log directory via directory listing. Access logs contain:

- All HTTP request paths (may include sensitive route parameters)
- Client IP addresses
- User-Agent strings
- Timestamps and request methods
- Potentially session tokens or credentials submitted in URLs

An unauthenticated attacker can browse the log listing, identify log file names by date, and download them to map user activity, discover other users' session data, and identify other vulnerable endpoints.

## Impact

Information disclosure of server activity and potential credential/token leakage from access log contents.

## Fix

Restrict `/support/logs` to authenticated admin users, or remove the endpoint entirely from production builds.
