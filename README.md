# secure-pipeline-lab

DevSecOps pipeline running against [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) as the intentionally vulnerable target.

---

## What this is

A GitHub Actions pipeline that scans the Juice Shop codebase on every push with four tools:

| Tool | Category | What it catches |
|------|----------|-----------------|
| [Semgrep](https://semgrep.dev) | SAST | Code patterns — injection, insecure deserialization, hardcoded secrets in logic |
| [Trivy](https://trivy.dev) | SCA + container | Vulnerable dependencies (`package.json`) and base image CVEs |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | Credentials, tokens, API keys committed to the repo |
| [OWASP ZAP](https://www.zaproxy.org) | DAST | Runtime vulnerabilities — XSS, SQLi, missing headers — against the running app |

The build breaks on any critical or high finding.

---

## The point

Running the tools is the easy part. The interesting work is what comes after the first scan drops 300+ findings:

1. **Classify** — which findings are real, which are false positives
2. **Tune** — write suppressions and custom rules until the signal-to-noise ratio is usable
3. **Document** — track the false-positive rate per tool before and after tuning

That documented tuning is the difference between "I ran a scanner" and knowing how to actually integrate SAST/DAST/SCA into a real pipeline.

---

## Status

- [x] Semgrep — 14 TPs documented, 0% FP rate after tuning
- [x] Trivy — 2 TPs (hardcoded RSA keys), 0 CVEs after `ignore-unfixed` filter, 0% FP rate
- [x] Gitleaks — configured; scans last commit for new secrets
- [ ] OWASP ZAP — baseline scan against running container
- [ ] False-positive analysis documented

---

## Upstream

OWASP Juice Shop is maintained at [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop). License: [MIT](LICENSE)
