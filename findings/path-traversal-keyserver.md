# Finding: Path Traversal — Encryption Key Server

| Field | Value |
|-------|-------|
| **File** | `routes/keyServer.ts` |
| **Line** | 14 |
| **Rule** | `javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal` |
| **Severity** | HIGH |
| **CWE** | CWE-22: Path Traversal |

## Vulnerable code

```typescript
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

## Source → Sink

**Source**: `params.file` (URL path parameter — attacker-controlled)  
**Sink**: `res.sendFile(path.resolve('encryptionkeys/', file))`

## Why it's exploitable

Same forward-slash-only check as `fileServer.ts`. The check is insufficient: backslashes and platform-specific path separators may bypass it depending on the OS.

**Note on direct traversal**: URL-encoded slashes (`..%2F`) are normalized by Express before reaching the handler and return 403 in runtime testing. The exploitable surface depends on platform (backslash on Windows) or middleware configuration.

**Note on impact**: the primary impact is already covered by the directory listing finding (`server.ts:298`) — `/encryptionkeys` is fully browsable without authentication, exposing `jwt.pub` directly. The path traversal extends the surface to escaping the `encryptionkeys/` boundary entirely.

## Proof of concept

```
GET /encryptionkeys/..%2Fetc%2Fpasswd
```

Blocked by Express path normalization in testing on `localhost:3000`. Exploitable via backslash on Windows or with middleware that does not normalize paths.

## Fix

```typescript
const safeFile = path.basename(params.file)
const resolvedPath = path.resolve('encryptionkeys/', safeFile)
if (!resolvedPath.startsWith(path.resolve('encryptionkeys'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
