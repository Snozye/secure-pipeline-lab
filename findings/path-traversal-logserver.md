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

Identical pattern to `keyServer.ts`. The `logs/` directory contains application access logs. While directory traversal into the logs directory is less severe than the encryption key server, the same bypass techniques allow escaping the `logs/` boundary to read arbitrary files. Additionally, log files themselves may contain sensitive data (session tokens, PII in request parameters).

## Proof of concept

```
GET /support/logs/..%2F..%2Fpackage.json
```

## Fix

```typescript
const safeFile = path.basename(params.file)
const resolvedPath = path.resolve('logs/', safeFile)
if (!resolvedPath.startsWith(path.resolve('logs'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
