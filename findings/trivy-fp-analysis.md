# Trivy — False Positive Analysis

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 2 |
| True Positives | 2 |
| False Positives | 0 |
| **FP Rate** | **0%** |
| CVEs found | 0 (all CRITICAL/HIGH filtered by `ignore-unfixed: true`) |

## What Trivy found

Trivy runs two scan types in this pipeline: `fs` (filesystem / SCA) and `image` (container). Both triggered on **secret detection**, not CVEs. No dependency CVEs surfaced after `ignore-unfixed: true` filtered unfixable findings.

---

## Finding 1 — RSA Private Key in Source Code

| Field | Value |
|-------|-------|
| **File** | `lib/insecurity.ts:21` |
| **Category** | Secret — `AsymmetricPrivateKey (private-key)` |
| **Severity** | HIGH |
| **Classification** | **True Positive** |

**Analysis**: RSA private key hardcoded directly in source code, used for JWT signing at line 54. This is the same finding documented in [`findings/hardcoded-jwt-key.md`](hardcoded-jwt-key.md) (also found by Semgrep rule `javascript.jsonwebtoken.security.jwt-hardcode`). The key is real and exploitable — an attacker can copy it from the public repository and forge admin JWTs.

Intentional Juice Shop vulnerability (`hardcodedJwtSecret` challenge).

---

## Finding 2 — RSA Private Key in Terraform IaC

| Field | Value |
|-------|-------|
| **File** | `terraform/networking.tf:171` |
| **Category** | Secret — `AsymmetricPrivateKey (private-key)` |
| **Severity** | HIGH |
| **Classification** | **True Positive** |

**Vulnerable code**:
```hcl
resource "aws_iam_server_certificate" "juice_shop_tls" {
  private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXA..." # vuln-code-snippet iacLeakedKeyChallenge
}
```

**Analysis**: A real RSA private key is hardcoded inline in a Terraform resource definition for an AWS IAM server certificate. In a real deployment, this key would be committed to version control, baked into IaC state files, and potentially exposed in Terraform plan outputs — all accessible to anyone with repository or CI/CD access.

This is a category of finding that SAST tools like Semgrep typically miss because they lack Terraform-specific secret rules. Trivy caught it; Semgrep did not. Intentional Juice Shop vulnerability (`iacLeakedKeyChallenge`).

---

## Notes on CVE findings

Trivy scanned `package.json` dependencies and the container image with `severity: CRITICAL,HIGH` and `ignore-unfixed: true`. No CVEs were reported, meaning:

- Any CRITICAL/HIGH CVEs in the dependency tree do not have a patched version available upstream
- `ignore-unfixed: true` correctly filtered these as unactionable — reporting a CVE with no fix available creates noise without enabling remediation

This is intentional pipeline behavior. When a fix is released for a dependency, `ignore-unfixed` will automatically surface it on the next run.

---

## Tool coverage comparison

| Finding | Semgrep | Trivy |
|---------|---------|-------|
| `lib/insecurity.ts` JWT key | ✅ Found | ✅ Found |
| `terraform/networking.tf` TLS key | ❌ Not found | ✅ Found |

Trivy provides coverage for IaC secrets that the Semgrep community rules do not cover, making both tools complementary.
