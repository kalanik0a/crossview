# LinkedIn Post — Crossview Alpha Launch

---

Two releases in one day. After shipping Touchstone (the hardware-bound consent layer for AI agents), here's its big brother:

Crossview — a cross-referenced MITRE intelligence silo + 5-stage code scanner.

One tool that holds 3,942 entities from CWE, CAPEC, ATT&CK (Enterprise/Mobile/ICS), ATLAS, D3FEND, and UKC in a single offline SQLite graph with 14,525 cross-references. Then scans your code and threads every finding through that graph.

The 5-stage pipeline:
1. Survey — walks your project, detects frameworks, enumerates entrypoints and sinks
2. Prematch — runs Bandit, Semgrep, detect-secrets, TruffleHog, Gitleaks, Trivy, Hadolint, OSV-Scanner
3. Investigate — walks CWE → CAPEC → ATT&CK → ATLAS → D3FEND → UKC for every finding, scores priority against CISA KEV
4. Verify — re-surveys live code per hypothesis, confirms or rejects
5. Report — Markdown + SARIF 2.1.0 + STIX 2.1

What makes it different: your finding isn't just "possible SQL injection." It's CWE-89 → CAPEC-66 → ATT&CK T1190 → D3FEND D3-SQLAM, with 847 CVEs in NVD, 23 in CISA KEV, 4 used in ransomware. That's the chain from weakness to real-world exploitation, automatically.

Includes a Textual TUI, in-process GraphQL API, NVD/KEV enrichment engine, and LLM intel fusion for grounded threat reports.

Double-audited against 32 CWE categories (all PASS). 5 automated SAST scanners clean. 26 findings found and fixed. MIT licensed.

It also pairs with Touchstone — when an AI agent uses Crossview to scan your code, Touchstone ensures the human approves the scan with hardware-bound consent.

GitHub: https://github.com/kalanik0a/crossview
Website: https://kalanik0a.github.io/crossview/
CWE Compliance: https://github.com/kalanik0a/crossview/blob/main/docs/cwe-compliance.md
Touchstone: https://github.com/kalanik0a/touchstone

#Security #MITRE #CWE #CAPEC #ATTCK #SAST #OpenSource #CyberSecurity #AI #AgenticAI #ThreatIntelligence #DevSecOps

---
