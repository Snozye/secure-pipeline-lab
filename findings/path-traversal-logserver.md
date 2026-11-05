# Finding: Path Traversal — Log File Server

| Field | Value |
|-------|-------|
| **File** | `routes/logfileServer.ts` |
| **Line** | 14 |
| **Rule** | `javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal` |
| **Severity** | HIGH |
| **CWE** | CWE-22: Path Traversal |

## Vulnerable code

```typescript
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('logs/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

## Source → Sink

**Source**: `params.file` (URL path parameter — attacker-controlled)  
**Sink**: `res.sendFile(path.resolve('logs/', file))`

## Why it's exploitable

Same forward-slash-only defense as the other file servers. In production, `logs/` contains application access logs with IP addresses, request paths, and potentially session tokens or PII in URL parameters.

**Note on direct traversal**: URL-encoded slashes (`..%2F`) are normalized by Express before reaching the handler and are blocked in runtime testing. The exploitable surface depends on platform or middleware configuration.

**Note on impact**: the primary impact is already covered by the directory listing finding (`server.ts:302`) — `/support/logs` is fully browsable without authentication. The path traversal would extend the surface to escaping the `logs/` boundary to read arbitrary files, but this is not exploitable via `..%2F` in the current setup. In development, `logs/` may be empty or not exist, further reducing practical impact.

**Lowest exploitability** of the four path traversal findings.

## Proof of concept

```
GET /support/logs/..%2F..%2Fpackage.json
```

Blocked by Express path normalization in testing on `localhost:3000`.

## Fix

```typescript
const safeFile = path.basename(params.file)
const resolvedPath = path.resolve('logs/', safeFile)
if (!resolvedPath.startsWith(path.resolve('logs'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
