# Finding: Directory Listing — /encryptionkeys

| Field | Value |
|-------|-------|
| **File** | `server.ts` |
| **Line** | 298 |
| **Rule** | `javascript.express.security.audit.express-serve-index-without-filter.express-serve-index-without-filter` |
| **Severity** | HIGH |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing |

## Vulnerable code

```typescript
app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
app.use('/encryptionkeys/:file', serveKeyFiles())
```

## Why it's a finding

This is the highest-severity directory listing: `/encryptionkeys` serves the JWT public key (`jwt.pub`) and potentially other cryptographic material. An attacker who browses this listing and downloads `jwt.pub` can:

1. Verify existing JWT tokens
2. If combined with the hardcoded private key (see `lib/insecurity.ts`), forge arbitrary JWT tokens for any user including admins

Directory listing here also reveals what key files exist, providing a roadmap for further attacks.

## Impact

Combined with the hardcoded private key, full authentication bypass: forge a JWT as any user ID.

## Fix

Remove directory listing. The public key can be served directly at a known path without enumeration:

```typescript
// No serveIndex — serve specific files only
app.use('/encryptionkeys/:file', serveKeyFiles())
```
