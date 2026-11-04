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

Same forward-slash-only check as `fileServer.ts`. The check is insufficient: URL-encoded slashes (`%2F`), backslashes, and other traversal sequences bypass it. An attacker could potentially escape the `encryptionkeys/` directory and read arbitrary files from the server filesystem — including the JWT private key if stored elsewhere, application configuration, or OS files.

## Proof of concept

```
GET /encryptionkeys/..%2F..%2F..%2Fetc%2Fpasswd
```

## Fix

```typescript
const safeFile = path.basename(params.file)
const resolvedPath = path.resolve('encryptionkeys/', safeFile)
if (!resolvedPath.startsWith(path.resolve('encryptionkeys'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
