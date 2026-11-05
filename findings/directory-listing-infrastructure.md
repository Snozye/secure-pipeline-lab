# Finding: Directory Listing — /infrastructure

| Field | Value |
|-------|-------|
| **File** | `server.ts` |
| **Line** | 269 |
| **Rule** | `javascript.express.security.audit.express-serve-index-without-filter.express-serve-index-without-filter` |
| **Severity** | MEDIUM |
| **CWE** | CWE-548: Exposure of Information Through Directory Listing |

## Vulnerable code

```typescript
app.use('/infrastructure', serveIndexMiddleware, serveIndex('infrastructure', { icons: true, view: 'details', filter: (filename) => filename !== 'README.md' }))
```

## Why it's a finding

The `serve-index` middleware renders a browsable HTML directory listing at `/infrastructure`. Visitors can enumerate all files in the `infrastructure/` directory — Terraform configurations, Dockerfiles, Kubernetes YAMLs. These files expose the application's cloud infrastructure layout, hardcoded resource names, and configuration that reduces attacker reconnaissance cost.

The `filter` only hides `README.md`; all other infrastructure files remain browsable.

## Impact

An attacker can enumerate cloud resource names, regions, service configurations, and security group rules from the Terraform files — information useful for targeting the cloud environment.

## Fix

Remove the `serveIndex` middleware entirely for sensitive directories, or restrict access to authenticated admin users only. Never expose infrastructure-as-code files in a production web server.
