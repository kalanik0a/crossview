# 10 · Enrichment

Enrichment is the half of Crossview that connects the static MITRE silo to **live, real-world threat intel**: which CVEs map to a weakness, which of those are being exploited in the wild (CISA KEV), affected platforms (CPE), and distilled MITRE page content. It all lands in `enrichment.db` (a mutable TTL cache), separate from the rebuildable reference silo.

## The enrichers

The registry lives in `crossview/enrichment/orchestrator.py` (`ALL_ENRICHERS`):

| Enricher | Scope | What it does |
|---|---|---|
| `cisa_kev` | global | Fetches CISA's Known Exploited Vulnerabilities catalog into the `kev` table. Small, fast, refresh often. |
| `cve_nvd_bulk` | global | Bulk-imports the NVD 2.0 feed into `cves` / `cwe_cves` / `cpes` / `cve_cpes`. Large and **resumable** via `sweep_state`. |
| `web_research` | per-entity | Fetches a canonical MITRE page (crawl4ai) and caches a distilled JSON payload in `enrichments`, keyed by `(entity_id, "web_research")`. |

`GLOBAL_ENRICHERS = {cisa_kev, cve_nvd_bulk}` take no entity; `PER_ENTITY_ENRICHERS = {web_research}` require one.

## Running enrichment

### CLI

```bash
# Global enrichers
crossview enrich --enricher cisa_kev          # pull the KEV catalog (do this first — it's cheap)
crossview enrich --enricher cve_nvd_bulk      # bulk NVD import (large, resumable)
crossview enrich                              # run all applicable global enrichers

# Per-entity
crossview enrich CWE-89                       # surfaces ranked CVEs + KEV intersection for a CWE
crossview research AML.T0051                  # web_research one entity (alias for the per-entity enricher)

# Bypass the TTL cache
crossview enrich CWE-89 --force
```

### Python

```python
from crossview.enrichment.orchestrator import run_enricher_sync, run_all_global_sync

run_enricher_sync("cisa_kev")
run_enricher_sync("web_research", entity_id="CWE-89")
run_all_global_sync(force=False)
```

Each returns an `EnrichmentResult` (`enricher`, `entity_id`, `payload`, `notes`, `side_effects`). See the [API Guide](05-api-guide.md#enrichment-orchestrator--crossviewenrichmentorchestrator).

## Caching & TTL

Cached payloads in `enrichments` carry `ttl_seconds` and a `fingerprint`. The orchestrator checks the cache before refetching (`cache.is_stale()`); `--force` / `force=True` bypasses it. The bulk NVD sweep records progress in `sweep_state` (`last_index`, `pages_done`, `status`), so an interrupted import resumes where it left off rather than restarting.

## NVD rate limits — going faster

The bulk NVD sweep (~361 k CVEs ≈ 181 pages) obeys NVD's published rate policy:

| Mode | Limit | Per-page delay | Full pull |
|---|---|---|---|
| Anonymous (default) | ~5 req / 30 s | ~6 s | ~18 min |
| **With an API key** | ~50 req / 30 s | ~0.8 s | **~2.4 min** |

Set an NVD API key (free from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)) to unlock the higher tier — the real de-throttle:

```bash
export NVD_API_KEY=…                      # sent as the `apiKey` header; ~10× faster
crossview enrich --enricher cve_nvd_bulk
```

`NVD_SLEEP` overrides the per-page delay if you want to tune it (floored at 0.5 s; too low just trips HTTP 429, which the exponential backoff then absorbs). Both knobs are read from the environment at run time.

## How the scanner consumes enrichment

Enrichment is read (never written) by the scan pipeline:

- **Stage 2d (`prematch-deps`)** joins each dependency CVE against `cwe_cves` and `kev`, escalating severity and tagging the message when a dependency CVE is in KEV.
- **Stage 3 (`investigate`)** calls `cve_enrichment()` to pull top CVEs by CVSS and KEV/ransomware counts for each hypothesis's CWE — these feed the [priority score](07-scanner-pipeline.md#priority-score--score_priority).
- **Triage** uses the KEV intersection to build its `kev_intersect` urgency bucket.
- **GraphQL** exposes it directly via `cves_for_cwe` and `kev_for_cwe`.

So the value of enrichment compounds: with KEV loaded, `crossview scan` and `crossview triage` can tell you which findings map to weaknesses that are being exploited *right now*.

## Recommended setup order

```bash
crossview update                              # 1. build the silo
crossview enrich --enricher cisa_kev          # 2. KEV — cheap, high-value
crossview enrich --enricher cve_nvd_bulk      # 3. NVD bulk — optional, large, resumable
# now scans and CWE lookups carry real-world exploitation signal
crossview enrich CWE-89
crossview scan /path/to/project
```

If you skip the NVD bulk import, per-CWE `enrich`/`research` still works on demand; you just won't have the full local CVE corpus for offline joins.

## Inspecting the cache

```python
from crossview.enrichment.cache import connect, stats
print(stats(connect()))     # counts: cves, cwe_cves, cpes, cve_cpes, kev, enrichments by enricher
```

## Web research vs. exploratory research

`web_research` / `crossview research` is **targeted** caching: give it a known entity ID, it fetches *that* canonical MITRE page and distills it. It is not a crawler. For open-ended, multi-source research ("everything about prompt injection in production AI"), use a dedicated research tool and feed conclusions back as entity lookups.

## crawl4ai prerequisites

`web_research` uses crawl4ai, which needs a Playwright browser the first time:

```bash
python -m playwright install chromium
```

If it can't start, the enricher returns a `notes` entry telling you exactly which command to run (using your active interpreter path).
