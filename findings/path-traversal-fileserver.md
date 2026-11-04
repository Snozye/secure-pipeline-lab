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

The null byte defense (`cutOffPoisonNullByte`) handles `%00` injection but does not cover all traversal vectors.

## Proof of concept

```
GET /ftp/%2F..%2F..%2Fetc%2Fpasswd
```

Or on Node.js, using backslash on certain platforms.

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
