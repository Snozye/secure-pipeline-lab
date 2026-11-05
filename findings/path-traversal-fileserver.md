# Finding: Path Traversal — FTP File Server

| Field | Value |
|-------|-------|
| **File** | `routes/fileServer.ts` |
| **Line** | 32 |
| **Rule** | `javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal` |
| **Severity** | HIGH |
| **CWE** | CWE-22: Path Traversal |

## Vulnerable code

```typescript
const file = params.file

if (!file.includes('/')) {
  verify(file, res, next)
}

function verify(file, res, next) {
  if (file && (endsWithAllowlistedFileType(file) || ...)) {
    file = security.cutOffPoisonNullByte(file)
    res.sendFile(path.resolve('ftp/', file))
  }
}
```

## Source → Sink

**Source**: `params.file` (URL path parameter — attacker-controlled)  
**Sink**: `res.sendFile(path.resolve('ftp/', file))`

## Why it's exploitable

The forward-slash check (`!file.includes('/')`) blocks simple traversal sequences like `../etc/passwd` but only checks for `/`. On Windows, `\` is also a path separator, and URL-encoded variants (`%2F`, `%5C`) may pass this check depending on the Express version and middleware.

The null byte defense (`cutOffPoisonNullByte`) is itself a vulnerability: it enables bypassing the allowlist extension check. The logic runs in this order:

1. `endsWithAllowlistedFileType('acquisitions.md%2500.pdf')` → passes (ends in `.pdf`)
2. `cutOffPoisonNullByte(...)` → strips everything from `%00` onward → `acquisitions.md`
3. `res.sendFile(path.resolve('ftp/', 'acquisitions.md'))` → serves the file without a permitted extension

**Note on impact**: the primary impact of this route is already covered by the directory listing finding (`server.ts:290`) — `/ftp` is fully browsable without authentication. The null byte vector extends the surface to files that lack an allowlisted extension, which would otherwise be blocked.

## Proof of concept

```
GET /ftp/acquisitions.md%2500.pdf
```

The server serves `acquisitions.md` despite the request appearing to end in `.pdf`.

Tested on `localhost:3000`: direct traversal (`..%2F`) is blocked by Express path normalization before reaching the handler. The null byte is the confirmed exploitable vector.

## Fix

Use `path.basename()` to strip any directory components before joining, then verify the resolved path stays within the intended directory:

```typescript
const safeFile = path.basename(file)
const resolvedPath = path.resolve('ftp/', safeFile)
if (!resolvedPath.startsWith(path.resolve('ftp'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
