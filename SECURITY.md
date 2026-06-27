# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Crossview, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **kalanik0a@proton.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours. Critical vulnerabilities will be patched and disclosed within 7 days.

## Scope

Crossview is a security scanner and MITRE reference silo. It executes external SAST tools (Bandit, Semgrep, TruffleHog, Gitleaks, Trivy, Hadolint, OSV-Scanner) as subprocesses and processes their output.

In scope for Crossview:
- Command injection via crafted project file paths or filenames
- SQL injection in reference.db, cohort.db, or enrichment.db queries
- SARIF/STIX/JSON deserialization vulnerabilities
- Path traversal in file scanning or report generation
- Secret leakage in scan reports or temp files
- Web research (crawl4ai) SSRF or data exfiltration
- GraphQL injection via the in-process schema
- Arbitrary code execution via crafted Python/TypeScript source files during harness analysis

Out of scope:
- Vulnerabilities in upstream SAST tools (report to their maintainers)
- MITRE data accuracy (report to MITRE)
- NVD/KEV data freshness (report to NIST/CISA)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.0-alpha | Yes |
