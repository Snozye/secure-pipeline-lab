# Finding: SQL Injection — Product Search

| Field | Value |
|-------|-------|
| **File** | `routes/search.ts` |
| **Line** | 23 |
| **Rule** | `javascript.sequelize.security.audit.sequelize-injection-from-request.sequelize-injection-from-request` |
| **Severity** | HIGH |
| **CWE** | CWE-89: SQL Injection |

## Vulnerable code

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

## Source → Sink

**Source**: `req.query.q` (URL query parameter — attacker-controlled)  
**Sink**: Raw Sequelize `query()` call with string interpolation

## Why it's exploitable

The length check (`criteria.length <= 200`) is not a security control — it only truncates oversized input, it does not sanitize it. The truncated string is still interpolated directly into the SQL query.

An attacker can craft a 200-character-or-shorter payload (SQL injection payloads are typically short) to perform UNION-based data extraction, boolean-based blind injection, or authentication bypass.

## Proof of concept

```
GET /rest/products/search?q=')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--
```

Leaks the database schema via UNION injection.

## Fix

Use Sequelize parameterized queries with `LIKE`:

```typescript
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { search: `%${criteria}%` } }
)
```
