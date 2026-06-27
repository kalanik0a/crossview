# 08 · Data Model

Column-level reference for the three SQLite databases. All use `sqlite3.Row` factories; the reference and cohort schemas live in `crossview/data/`, the enrichment schema in `crossview/enrichment/cache.py`.

> Column lists below describe the schema's intent and the fields the code reads/writes. Treat the source modules (`data/database.py`, `data/cohort.py`, `enrichment/cache.py`) as authoritative if you need exact DDL.

---

## Reference DB — `crossview.db`

Location: `<data-dir>/crossview.db`. Rebuilt by `crossview update`.

### `entities`

The canonical MITRE entity table — one row per CWE / CAPEC / ATT&CK / ATLAS / D3FEND / UKC entity.

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | Canonical ID — `CWE-89`, `CAPEC-66`, `T1059`, `AML.T0051`, `D3F:…`, `UKC-7` |
| `source` | TEXT | `cwe` \| `capec` \| `attack` \| `atlas` \| `d3fend` \| `ukc` |
| `subtype` | TEXT | `weakness`, `category`, `view`, `attack-pattern`, `technique`, `tactic`, `matrix`, `mitigation`, `asset`, `kill-chain-phase`, `stage` |
| `name` | TEXT | Human-readable title |
| `description` | TEXT | Full text (default `''`) |
| `framework` | TEXT? | ATT&CK: `enterprise`/`mobile`/`ics`; ATLAS: `atlas`; else NULL |
| `abstraction` | TEXT? | CAPEC: `Standard`/`Detailed`/`Meta`; CWE: `class`/`base`/`variant` |
| `stix_id` | TEXT? | Source STIX UUID, used to resolve relationships during load |
| `created_at`, `modified_at` | TEXT? | ISO timestamps |
| `raw_json` | TEXT? | Source-specific payload, preserved for fidelity |

Indexes: `source`, `subtype`, `framework`, `stix_id`.

### `xrefs`

Directed, typed edges of the knowledge graph.

| Column | Type | Notes |
|---|---|---|
| `src_id` | TEXT | Source entity ID |
| `dst_id` | TEXT | Destination entity ID |
| `relation` | TEXT | See relation taxonomy below |
| `source` | TEXT | Which dataset asserted the edge |
| `metadata_json` | TEXT? | Optional edge metadata |

Primary key: `(src_id, dst_id, relation)`. Indexes: `(src_id, relation)`, `(dst_id, relation)`.

**Relation taxonomy**

| Relation | Meaning |
|---|---|
| `child_of` | Hierarchy (CWE/CAPEC parent) |
| `targets` | Weakness→attack-pattern, or attack-pattern→asset |
| `uses_weakness` | CAPEC→CWE (inverse of `targets`) |
| `related` | Peer link (e.g. CAPEC→ATT&CK technique) |
| `chains_to` | Attack chain (CAPEC CanPrecede) |
| `mitigates` | Mitigation→technique/weakness |
| `counters` | D3FEND→ATT&CK technique |
| `kill_chain_phase` | Technique→UKC phase / ATT&CK tactic |

### `entities_fts`

FTS5 virtual table (`id UNINDEXED, name, description`, porter unicode61 tokenizer) mirroring `entities`. Repopulated by `rebuild_fts()` after a load; backs the `search` command and the GraphQL `search` resolver.

---

## Enrichment DB — `enrichment.db`

Location: `<data-dir>/enrichment.db`. Mutable TTL cache.

### `cves`

| Column | Type | Notes |
|---|---|---|
| `cve_id` | TEXT PK | `CVE-YYYY-NNNNN` |
| `description` | TEXT? | English description |
| `cvss_v3_score` | REAL? | Base score |
| `cvss_v3_severity` | TEXT? | CRITICAL/HIGH/MEDIUM/LOW/NONE |
| `published_at`, `modified_at` | TEXT? | ISO timestamps |
| `raw_json` | TEXT? | Trimmed in bulk sweep |
| `fetched_at` | TEXT | Load time |

Indexes: `cvss_v3_severity`, `published_at`.

### `cwe_cves`
Many-to-many CWE↔CVE. `(cwe_id, cve_id)` PK; index on `cve_id`. `cwe_id` points into `crossview.db` `entities.id`.

### `cpes`
Platform dictionary. `cpe_uri` PK; `part`, `vendor`, `product`, `version`, `raw_json`. Index on `(vendor, product)`.

### `cve_cpes`
Many-to-many CVE↔CPE. `(cve_id, cpe_uri)` PK; `vulnerable` (0/1, default 1); index on `cpe_uri`.

### `kev`
CISA Known Exploited Vulnerabilities.

| Column | Notes |
|---|---|
| `cve_id` PK | |
| `vendor_project`, `product`, `vulnerability_name` | |
| `date_added` | When CISA cataloged it (indexed) |
| `short_description`, `required_action`, `due_date` | |
| `known_ransomware_use` | |
| `notes` | |
| `cwe_ids_json` | JSON array of CWE IDs, e.g. `["CWE-89"]` — matched via LIKE in resolvers |
| `fetched_at` | |

### `enrichments`
Generic per-entity payload cache.

| Column | Notes |
|---|---|
| `id` PK (autoinc) | |
| `entity_id` | → `crossview.db` `entities.id` |
| `enricher` | `cve_nvd_bulk` \| `cisa_kev` \| `web_research` |
| `payload_json` | The enricher's JSON result |
| `fetched_at` | |
| `ttl_seconds` | Stale-after window (nullable) |
| `fingerprint` | Idempotency token (nullable) |

Unique `(entity_id, enricher)`; indexes on `entity_id`, `enricher`.

### `sweep_state`
Resumable bulk-import progress. `sweep_name` PK; `last_index`, `total_expected`, `pages_done`, `started_at`, `last_progress_at`, `status` (`idle`/`running`/`complete`/`error`).

---

## Cohort DB — `<project>/.crossview/cohort.db`

One per scanned project. Created non-destructively on first `cohort.connect()`. References canonical entities by ID; can `ATTACH` the reference DB as `ref`.

### Stage 1 (survey) output

**`project_map`** — `project_path` PK, `surveyed_at`, `languages_json`, `frameworks_json`, `files_count`, `entrypoints_count`, `sinks_count`, `notes`.

**`entrypoints`**

| Column | Notes |
|---|---|
| `id` PK | |
| `project_path`, `file_path`, `line` | location |
| `kind` | `http_route` \| `cli_command` \| `websocket` \| `scheduled` \| … |
| `framework` | `fastapi` \| `flask` \| `django` \| … |
| `method`, `path`, `handler_name`, `parameters_json` | route detail |
| `surveyed_at` | |

Unique `(project_path, file_path, line, kind)`; indexes on `project_path`, `kind`.

**`sinks`**

| Column | Notes |
|---|---|
| `id` PK | |
| `project_path`, `file_path`, `line` | location |
| `kind` | `sql_exec` \| `shell_exec` \| `code_eval` \| `llm_call` \| … |
| `callee` | function/method name |
| `risk_cwe_json` | candidate CWE IDs, e.g. `["CWE-89"]` |
| `snippet` | code context |
| `surveyed_at` | |

Unique `(project_path, file_path, line, callee)`; indexes on `project_path`, `kind`, `file_path`.

### Stage 2 (prematch) output

**`scan_results`** — raw SAST findings.

| Column | Notes |
|---|---|
| `id` PK | |
| `project_path`, `file_path`, `line_start`, `line_end` | location |
| `rule_id`, `rule_source` | the tool + rule |
| `severity` | error/warning/note |
| `message` | |
| `cwe_id` | → `entities.id` (optional) |
| `raw_finding_json` | original tool output |
| `scanned_at` | |

Indexes on `cwe_id`, `file_path`.

### Investigation lifecycle

**`investigations`** — `id` PK, `project_path`, `file_path`, `line_start`, `line_end`, `summary`, `status` (`open`/`validated`/…), `scanner_finding_id` → `scan_results.id`, `opened_at`, `closed_at`. Indexes on `status`, `file_path`.

**`hypotheses`** — the parent/child hypothesis forest.

| Column | Notes |
|---|---|
| `id` PK | |
| `investigation_id` | → `investigations.id` ON DELETE CASCADE |
| `parent_id` | → `hypotheses.id` (forest structure) |
| `statement` | |
| `confidence` | REAL, default 0.5 |
| `suspected_cwe`, `suspected_capec`, `suspected_attack`, `suspected_atlas` | → `entities.id` |
| `status` | `active`/`confirmed`/`partial`/`rejected`/`superseded` |
| `superseded_by` | → `hypotheses.id` |
| `posted_at` | |

Indexes on `investigation_id`, `parent_id`, `status`.

**`evidence`** — `id` PK, `hypothesis_id` → `hypotheses.id` CASCADE, `kind` (`mitre_xref`/`external_ref`/`test_result`/…), `content`, `file_path`, `line`, `ref_url`, `created_at`. Index on `hypothesis_id`.

**`validations`** — `id` PK, `hypothesis_id` CASCADE, `entity_type` (`cwe`/`capec`/`attack`/`atlas`/`d3fend`/`ukc`), `entity_id` → `entities.id`, `match`, `notes`, `created_at`. Index on `hypothesis_id`.

**`mitigations`** — `id` PK, `investigation_id` CASCADE, `d3fend_id` → `entities.id`, `description`, `status` (`proposed`/`applied`), `applied_at`, `verified_at`.

**`notes`** — `id` PK, `investigation_id` CASCADE, `content`, `created_at`.

---

## Cross-database joins

The reference DB is the hub. Two common cross-DB patterns:

**Cohort → reference** (resolve canonical names for findings), via `ATTACH`:

```sql
-- after cohort.attach_reference(conn, ref_db, alias='ref')
SELECT h.statement, e.name
FROM hypotheses h
JOIN ref.entities e ON h.suspected_cwe = e.id
WHERE h.status = 'confirmed';
```

**Reference CWE → enrichment CVEs** (what `cves_for_cwe` does):

```sql
SELECT c.cve_id, c.cvss_v3_score, c.cvss_v3_severity,
       EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = c.cve_id) AS in_kev
FROM cwe_cves cc
JOIN cves c ON c.cve_id = cc.cve_id
WHERE cc.cwe_id = 'CWE-89'
ORDER BY c.cvss_v3_score DESC;
```

For live numbers, `crossview dev stats` (reference) and `enrichment.cache.stats()` (enrichment) report per-table counts.
