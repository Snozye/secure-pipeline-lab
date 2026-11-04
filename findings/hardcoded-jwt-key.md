# Finding: Hardcoded RSA Private Key (JWT Signing)

| Field | Value |
|-------|-------|
| **File** | `lib/insecurity.ts` |
| **Line** | 54 |
| **Rule** | `typescript.jwt.security.audit.jwt-hardcode.jwt-express-hardcoded` |
| **Severity** | HIGH |
| **CWE** | CWE-321: Use of Hard-coded Cryptographic Key |

## Vulnerable code

```typescript
// lib/insecurity.ts:21
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqL...[truncated]\r\n-----END RSA PRIVATE KEY-----'

// lib/insecurity.ts:54
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

## Source → Sink

**Source**: Hardcoded RSA private key string in source code  
**Sink**: `jwt.sign(user, privateKey)` — used to sign every authentication token

## Why it's exploitable

The RSA private key is hardcoded in the source file. Because this is an open-source application, the key is publicly known. Anyone can:

1. Copy the private key from the GitHub repository
2. Use it to sign arbitrary JWT payloads with `jwt.sign({ id: 1, email: 'admin@juice-sh.op', role: 'admin' }, privateKey, { algorithm: 'RS256' })`
3. Send the forged token as the `Authorization` header to gain admin access

The `encryptionkeys/jwt.pub` public key is also browsable via the directory listing finding, though the private key is what enables forgery.

## Attack chain

GitHub source → copy `privateKey` → sign `{"id":1,"role":"admin"}` → `Authorization: Bearer <forged>` → full admin access

## Fix

Load the private key from an environment variable or secrets manager at runtime:

```typescript
const privateKey = process.env.JWT_PRIVATE_KEY ?? fs.readFileSync('/run/secrets/jwt_private_key', 'utf8')
```

Never commit cryptographic keys to source control, even in test/demo applications.
