# Substack Article — Crossview: Your Code in the MITRE Graph

---

## Crossview: Every Finding Mapped to the Full MITRE Taxonomy

### The scanner that thinks in chains, not findings

Security scanners tell you "possible SQL injection at line 42." That's useful. But it's not intelligence. Intelligence is: this weakness (CWE-89) enables this attack pattern (CAPEC-66, SQL Injection), which maps to this adversary technique (ATT&CK T1190, Exploit Public-Facing Application), which is countered by this defense (D3FEND D3-SQLAM, SQL Audit Monitoring), and this weakness class has 847 CVEs in NVD, 23 in CISA's Known Exploited Vulnerabilities catalog, 4 confirmed used in ransomware campaigns.

That's what Crossview does. It takes every finding from your SAST tools, walks it through the canonical MITRE graph, enriches it with real-world exploitation data, and tells you not just what's wrong — but how bad it actually is in the wild.

### The architecture

**The Silo**: 3,942 entities from seven MITRE frameworks — CWE, CAPEC, ATT&CK (Enterprise, Mobile, ICS), ATLAS, D3FEND, and UKC (Unified Kill Chain) — stored in one offline SQLite database with 14,525 cross-references. Full-text search, GraphQL API, Textual TUI.

**The Scanner**: A 5-stage pipeline that takes a project from "unscanned" to "fully mapped against the MITRE taxonomy":

1. **Survey** — Walks your code, detects frameworks (Flask, Django, FastAPI, Next.js, Express, Hono, NestJS, Anthropic, OpenAI, LangChain), enumerates HTTP routes, CLI commands, scheduled tasks, and catalogs sinks (SQL, shell, eval, deserialization, HTTP, templating, LLM calls) with CWE mappings.

2. **Prematch** — Runs eight external SAST tools in parallel: Bandit, Semgrep, detect-secrets, TruffleHog (with live credential verification), Gitleaks, Trivy, Hadolint, and OSV-Scanner. Normalizes all output into a unified finding model.

3. **Investigate** — For each finding, walks the cross-source chain: CWE → CAPEC → ATT&CK → ATLAS → D3FEND → UKC. Scores priority using KEV presence, CVSS scores, and chain depth. Optionally web-researches top CWEs for additional context.

4. **Verify** — Re-surveys live code per hypothesis. Checks file existence, line match, entrypoint reachability. Classifies: confirmed, partial, rejected.

5. **Report** — Emits Markdown (human-readable), SARIF 2.1.0 (GitHub Code Scanning / VS Code), and STIX 2.1 (threat intelligence platforms).

**The Enrichment Engine**: CISA KEV (daily JSON feed), NVD CVE (bulk sweep via NVD 2.0 API, paginated, resumable), and web research (crawl4ai scraping of MITRE/NVD pages). All cached in local SQLite with TTL management.

### What it found (case study)

We pointed Crossview at a small open-source web application. In 70 seconds, it:

- Surveyed 47 Python files, detected Flask + SQLAlchemy
- Found 15 findings across Bandit and Semgrep
- Walked each through the MITRE graph, producing 15 confirmed chains
- Intersected with CISA KEV: the top weakness class (CWE-89) has 23 actively-exploited CVEs, 4 in ransomware
- Generated a ranked report from "anonymous HTTP request to remote code execution" — one chain, every link cross-referenced

The case study video is on the project site.

### The security posture

A security scanner should be secure itself. We double-audited Crossview:

- 2 independent audit passes across all 74 Python files (9,147 lines)
- 26 vulnerabilities found and fixed (4 HIGH, 6 MEDIUM)
- 32 CWE categories checked — all PASS
- 5 automated SAST scanners clean (Bandit, Semgrep, detect-secrets, Gitleaks, Trivy)

Key fixes: Zip Slip prevention in MITRE data extraction, XSS autoescaping in HTML reports, secret value stripping from the investigation database, GraphQL variable parameterization, path traversal boundary checks.

The full CWE compliance matrix is in the repository.

### Agent-ready

Crossview works as a Claude Code skill — the AI agent invokes `crossview scan /path/to/project` and receives structured SARIF findings. Combined with Touchstone (our hardware-bound consent tool, also released today), this creates a complete security workflow:

1. AI agent wants to scan code → calls Crossview
2. Touchstone opens a consent window → human reviews the scan command, touches YubiKey
3. Crossview runs the 5-stage pipeline → returns findings
4. Agent uses findings to fix vulnerabilities

The trust anchor (Touchstone) ensures the human approves. The scanner (Crossview) provides the intelligence. Together, they're the security stack for agentic AI.

### Get it

Crossview is MIT licensed. Self-hosted. Alpha release.

```bash
git clone https://github.com/kalanik0a/crossview
cd crossview
make install
crossview update        # download MITRE data
crossview scan ./myapp  # run the full pipeline
```

GitHub: https://github.com/kalanik0a/crossview
Website: https://kalanik0a.github.io/crossview/
Documentation: https://github.com/kalanik0a/crossview/tree/main/docs
CWE Compliance: https://github.com/kalanik0a/crossview/blob/main/docs/cwe-compliance.md
Touchstone: https://github.com/kalanik0a/touchstone

---

*Sean Jeffery Kalanikoa Lum is a security engineer with 20+ years in IT. Crossview was built to solve a problem he kept hitting: security findings that exist in isolation, disconnected from the taxonomy that explains why they matter. Touchstone and Crossview were shipped on the same day — June 26, 2026 — as complementary halves of the agentic AI security stack.*

---
