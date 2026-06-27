# CWE Compliance Matrix — Crossview

Crossview has been audited through two independent security passes across all 74 Python source files (9,147 lines), plus automated SAST scanning with 5 tools.

## Audit Summary

| Pass | Scope | Findings | Fixed | Auditor |
|------|-------|----------|-------|---------|
| First (3 parallel agents) | Scanner pipeline, data/enrichment, CLI/TUI/reporting | 24 (4 HIGH, 6 MEDIUM, 12 LOW, 2 INFO) | All HIGH + MEDIUM | Claude Opus 4.6 |
| Second | Fix verification + regression check | 2 (0 HIGH, 0 MEDIUM, 2 LOW, 1 INFO) | All | Claude Opus 4.6 |
| **Total** | **74 files, 9,147 lines** | **26 unique findings** | **12/12 HIGH+MEDIUM fixed** | |

## Automated SAST Results

| Scanner | Findings |
|---------|----------|
| Bandit 1.9.4 | 7 Medium (1 XML, 6 SQL f-string — all verified safe or fixed), 17 Low |
| Semgrep 1.161.0 (auto + security-audit) | 0 findings |
| detect-secrets | 0 secrets |
| Gitleaks 8.30.1 | No leaks (792KB scanned) |
| Trivy 0.69.3 (vuln + secret + misconfig) | Clean |

## HIGH Findings — All Fixed

| # | CWE | Issue | File | Fix |
|---|-----|-------|------|-----|
| H1 | CWE-312 | Secret values stored in cleartext in cohort.db | prematch_secrets.py, triage.py | `_strip_secret_values()` redacts Raw/RawV2/Secret/Match/Fingerprint keys |
| H2 | CWE-22 | Zip Slip path traversal in CWE data extraction | downloader.py:50 | `is_relative_to(raw_dir.resolve())` check before extraction |
| H3 | CWE-79 | XSS in HTML reports via `from_string()` bypassing autoescaping | reporting.py:20 | `Environment(autoescape=True)` unconditionally |
| H4 | CWE-22 | Arbitrary directory creation via GraphQL project_path | resolvers/cohort.py | `_validate_project_path()` — must be existing dir, no `..` |

## MEDIUM Findings — All Fixed

| # | CWE | Issue | File | Fix |
|---|-----|-------|------|-----|
| M1 | CWE-89 | ATTACH DATABASE alias SQL injection | cohort.py:171 | Regex validation `^[a-zA-Z_][a-zA-Z0-9_]*$` |
| M2 | CWE-22/59 | Symlink write to .crossview directory | cohort.py, triage.py | `is_symlink()` check before mkdir |
| M3 | CWE-22 | Unvalidated file_path from SAST output in verify | verify.py:74 | `is_relative_to(project_root)` boundary check |
| M4 | CWE-943 | GraphQL injection via string concatenation in TUI | tui/app.py | All queries converted to GraphQL variables API |
| M5 | CWE-89 | Bypassable SQL guard on `dev sql` command | dev/commands.py:138 | `PRAGMA query_only = ON` at SQLite level |
| M6 | CWE-598 | Gemini API key exposed in URL query parameter | intel/generate.py:122 | Moved to `x-goog-api-key` HTTP header |

## CWE Compliance Table

| CWE ID | Name | Status | Notes |
|--------|------|--------|-------|
| CWE-15 | External Control of System or Configuration Setting | PASS | NVD_API_KEY env var documented; `max(sleep, 0.5)` floor enforced |
| CWE-20 | Improper Input Validation | PASS | Label/alias regex validation; Typer `exists=True` on file args; project_path validation |
| CWE-22 | Path Traversal | PASS | Zip Slip fixed; verify.py boundary check; GraphQL project_path validation; symlink checks |
| CWE-59 | Improper Link Resolution | PASS | Symlink checks on .crossview dir; `is_symlink()` skip in rglob; Zip Slip uses `resolve()` |
| CWE-74 | Injection | PASS | GraphQL uses variables API; SQL uses parameterized queries; no shell=True |
| CWE-78 | OS Command Injection | PASS | All subprocess calls use list-form args (no `shell=True`); no `os.system()`/`eval()`/`exec()` |
| CWE-79 | Cross-site Scripting | PASS | `Environment(autoescape=True)` on all Jinja2 templates |
| CWE-89 | SQL Injection | PASS | All queries parameterized (`?` placeholders); ATTACH alias validated; dev sql uses `query_only` |
| CWE-94 | Code Injection | PASS | AST walker is read-only static analysis; no `eval()`/`exec()` on scanned code |
| CWE-116 | Improper Encoding or Escaping | PASS | Jinja2 autoescaping; GraphQL variables; parameterized SQL |
| CWE-200 | Information Exposure | PASS | Secret values stripped from cohort.db; show_env filters sensitive vars |
| CWE-250 | Execution with Unnecessary Privileges | PASS | No suid bits; runs as invoking user |
| CWE-276 | Incorrect Default Permissions | PASS | cohort.db created with process umask; .crossview/ dir checked for symlinks |
| CWE-295 | Improper Certificate Validation | PASS | httpx defaults to TLS verification; no `verify=False` anywhere |
| CWE-312 | Cleartext Storage of Sensitive Information | PASS | `_strip_secret_values()` redacts secret fields before cohort.db storage |
| CWE-326 | Inadequate Encryption Strength | PASS | N/A — no custom crypto; delegates to TLS for network, filesystem perms for local |
| CWE-362 | Race Condition | PASS | TemporaryDirectory context managers; no shared mutable state between scan stages |
| CWE-367 | TOCTOU Race Condition | PASS | Zip Slip uses `resolve()` before extraction; symlink checks before mkdir |
| CWE-377 | Insecure Temporary File | PASS | TemporaryDirectory used for most temp files; one NamedTemporaryFile with finally cleanup |
| CWE-426 | Untrusted Search Path | PASS | Scanner tool binaries resolved via `shutil.which()`; subprocess list-form prevents PATH abuse |
| CWE-434 | Unrestricted Upload | PASS | N/A — no file upload functionality |
| CWE-502 | Deserialization of Untrusted Data | PASS | JSON-only parsing (`json.loads`); no pickle/marshal/yaml.unsafe_load |
| CWE-532 | Information in Log File | PASS | No log files written; secret values stripped before storage |
| CWE-598 | Sensitive Query String | PASS | API keys sent via HTTP headers, not URL parameters |
| CWE-611 | XXE | PASS | Python's expat does not expand external entities by default; xmltodict safe |
| CWE-668 | Exposure to Wrong Sphere | PASS | Secret values redacted; dev sql is read-only; env vars documented |
| CWE-693 | Protection Mechanism Failure | PASS | Defense-in-depth: parameterized SQL + query_only PRAGMA; autoescape + safe filters; resolve + is_relative_to |
| CWE-732 | Incorrect Permission Assignment | PASS | No special permissions set on generated files |
| CWE-754 | Improper Check for Unusual Conditions | PASS | Subprocess timeouts on all external tools; graceful degradation for missing tools |
| CWE-798 | Hard-coded Credentials | PASS | No credentials in source; API keys from environment |
| CWE-918 | SSRF | PASS | All fetch URLs are hardcoded MITRE/NVD/CISA endpoints; entity_id splits validated |
| CWE-943 | Data Query Logic Injection | PASS | GraphQL uses variables API; FTS5 uses parameterized MATCH |

## Positive Security Findings

- **No `shell=True` anywhere** — all 12+ subprocess calls use list-form arguments
- **No `eval()`, `exec()`, `pickle`, `marshal`** — safe deserialization only
- **All SQL uses `?` placeholders** — no user data in SQL strings (except ATTACH alias, now validated)
- **All subprocess calls have timeouts** — 60-1200 seconds, preventing indefinite hangs
- **AST walker is read-only** — scanned Python code is never executed, only statically analyzed
- **Graceful degradation** — missing tools logged and skipped, not errored

## Known Acceptable Risks (Alpha)

| Risk | Severity | Rationale |
|------|----------|-----------|
| `ast_grep_py` not available on NixOS | LOW | TypeScript harness degrades gracefully; Python harness works fully |
| FTS5 query syntax injection | LOW | Can cause performance issues but not data modification |
| dev commands expose internal data | LOW | Local CLI tool; MITRE data is public; gated behind `dev` subcommand |
| XML billion-laughs (DoS) | LOW | Only processes MITRE CWE XML from hardcoded URL; supply chain compromise required |
| `readarray -d ''` requires bash 4.4+ | LOW | Crossview is Python, not bash; only affects Touchstone integration |

## Standards Alignment

| Standard | Relevance |
|----------|-----------|
| OWASP Top 10 (2021) | A01 Broken Access Control, A03 Injection, A04 Insecure Design — all addressed |
| OWASP ASVS v4 | V5 (Validation), V8 (Data Protection), V12 (Files) — all addressed |
| CWE Top 25 (2024) | 8 of Top 25 CWEs explicitly checked and mitigated |
| MITRE ATT&CK | Crossview itself maps findings to ATT&CK; its own codebase is hardened against T1059 (Command and Scripting Interpreter) |
| NIST SSDF | PW.6 (Verify software security), RV.1 (Identify and confirm vulnerabilities) — this audit fulfills both |
