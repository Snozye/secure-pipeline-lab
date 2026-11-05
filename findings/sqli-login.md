# Finding: SQL Injection — Login

| Field | Value |
|-------|-------|
| **File** | `routes/login.ts` |
| **Line** | 34 |
| **Rule** | `javascript.sequelize.security.audit.sequelize-injection-from-request.sequelize-injection-from-request` |
| **Severity** | HIGH |
| **CWE** | CWE-89: SQL Injection |
| **Runtime confirmed** | ✅ Yes |

## Vulnerable code

```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

## Source → Sink

**Source**: `req.body.email` (HTTP POST body — attacker-controlled)  
**Sink**: Raw Sequelize `query()` call with string interpolation

## Why it's exploitable

`req.body.email` is interpolated directly into the SQL string with no parameterization or sanitization. An attacker can supply `' OR 1=1--` as the email to bypass authentication entirely, or use more complex payloads for data extraction.

The password field goes through `security.hash()` (MD5) before interpolation, so it is not injectable via the password parameter.

## Proof of concept

```
POST /rest/user/login
{"email":"' OR 1=1-- -","password":"anything"}
```

Returns the first user in the table (admin). **Confirmed in runtime** — payload `' OR 1=1-- -` bypasses authentication and logs in as the admin account.

## Fix

Replace raw string interpolation with Sequelize parameterized queries:

```typescript
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: { email: req.body.email, password: security.hash(req.body.password || '') },
    model: UserModel,
    plain: true
  }
)
```
