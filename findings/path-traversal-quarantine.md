# Finding: Path Traversal — Quarantine File Server

| Field | Value |
|-------|-------|
| **File** | `routes/quarantineServer.ts` |
| **Line** | 14 |
| **Rule** | `javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal` |
| **Severity** | HIGH |
| **CWE** | CWE-22: Path Traversal |

## Vulnerable code

```typescript
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('ftp/quarantine/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

## Source → Sink

**Source**: `params.file` (URL path parameter — attacker-controlled)  
**Sink**: `res.sendFile(path.resolve('ftp/quarantine/', file))`

## Why it's exploitable

Same forward-slash-only defense as the other file servers. The quarantine directory holds uploaded files that failed malware scanning — serving them is intentionally restricted. Path traversal out of `ftp/quarantine/` could expose files in the broader `ftp/` directory or beyond, including sensitive documents intentionally placed there for challenges (e.g., `acquisitions.md`, `www-data.bak`).

## Proof of concept

```
GET /ftp/quarantine/..%2Facquisitions.md
```

## Fix

```typescript
const safeFile = path.basename(params.file)
const resolvedPath = path.resolve('ftp/quarantine/', safeFile)
if (!resolvedPath.startsWith(path.resolve('ftp/quarantine'))) {
  return res.status(403).end()
}
res.sendFile(resolvedPath)
```
