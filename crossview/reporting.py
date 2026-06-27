"""Shared report engine — client-grade HTML (always) + PDF (when a renderer is
available), across Crossview's use cases:

    render_findings_html  — Vulnerability Research / Exploit Chain (scan findings)
    render_intel_html     — OSCTI (Intellio-style threat-intel reports)
    render_artifact_html  — Binary Analysis (capa/YARA/LIEF; scaffold)

All three share one branded, print-ready template base. PDF is tried via
WeasyPrint → headless Chromium (Playwright) → skipped gracefully.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path

from jinja2 import Environment

# [CWE-79] Force autoescaping on ALL templates, including from_string().
# select_autoescape only applies to file-loaded templates with matching extensions.
_env = Environment(autoescape=True)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


_CSS = """
  :root{ --ink:#16202a; --mute:#5b6b78; --line:#d8e0e6; --cy:#0a6ea8; --navy:#0c2233;
         --hi:#c0392b; --med:#c87f0a; --low:#5b6b78; --bg:#f4f7f9; }
  *{box-sizing:border-box}
  html{font-family:"DejaVu Sans",Helvetica,Arial,sans-serif;color:var(--ink);font-size:11pt;line-height:1.5}
  body{margin:0;background:#fff}
  @page{ size:A4; margin:18mm 16mm 20mm 16mm;
    @bottom-center{ content:"Crossview · {{ kind_label }} · page " counter(page) " / " counter(pages);
                    font-size:8pt; color:#5b6b78; } }
  .cover{ background:var(--navy); color:#eaf3f8; padding:26px 28px; border-bottom:4px solid var(--cy); }
  .cover .kind{ font-family:"DejaVu Sans Mono",monospace; color:#7fb6d6; font-size:8.5pt; letter-spacing:.18em; text-transform:uppercase }
  .cover h1{ margin:4px 0 0; font-size:23pt; }
  .cover .sub{ font-family:"DejaVu Sans Mono",monospace; color:#9ec7dd; margin-top:6px; font-size:9.5pt }
  .wrap{ padding:22px 28px }
  .meta{ font-family:"DejaVu Sans Mono",monospace; font-size:9pt; color:var(--mute); margin:10px 0 6px }
  .summary{ display:flex; gap:10px; margin:14px 0 8px; flex-wrap:wrap }
  .stat{ border:1px solid var(--line); border-radius:8px; padding:10px 16px; background:var(--bg); min-width:118px }
  .stat b{ font-size:20pt; display:block; color:var(--navy) } .stat.r b{ color:var(--hi) } .stat.a b{ color:var(--med) }
  .stat span{ font-size:8.5pt; color:var(--mute); text-transform:uppercase; letter-spacing:.08em }
  h2.section{ margin:24px 0 6px; padding-bottom:6px; border-bottom:2px solid var(--cy); color:var(--navy); font-size:14.5pt }
  .card{ border:1px solid var(--line); border-radius:8px; margin:12px 0; page-break-inside:avoid; overflow:hidden }
  .card > .head{ display:flex; align-items:center; gap:10px; padding:10px 14px; background:var(--bg); border-bottom:1px solid var(--line) }
  .card .loc{ font-family:"DejaVu Sans Mono",monospace; font-size:9.5pt; color:var(--navy); flex:1; word-break:break-all }
  .card .body{ padding:12px 14px } .card h3{ margin:0 0 6px; font-size:11.5pt; color:var(--navy) } .card .msg{ margin:0 0 10px }
  .badge{ font-size:8pt; font-weight:700; padding:2px 8px; border-radius:10px; color:#fff; letter-spacing:.05em }
  .sev-high{ background:var(--hi) } .sev-med{ background:var(--med) } .sev-low{ background:var(--low) }
  .conf,.rule{ font-family:"DejaVu Sans Mono",monospace; font-size:8.5pt; color:var(--mute) }
  table.x{ width:100%; border-collapse:collapse; margin:8px 0; font-size:9pt }
  table.x th,table.x td{ border:1px solid var(--line); padding:5px 8px; text-align:left; vertical-align:top }
  table.x th{ background:#eef3f6; color:var(--navy); font-weight:600; width:150px; white-space:nowrap }
  code{ font-family:"DejaVu Sans Mono",monospace; background:#eef3f6; padding:1px 4px; border-radius:3px }
  .kev{ color:var(--hi); font-weight:600 } .ok{ color:#1a7f4b } .no{ color:var(--mute) }
  ul{ margin:6px 0; padding-left:18px } li{ margin:2px 0 }
  .method{ margin-top:24px; font-size:9.5pt; color:var(--mute); border-top:1px solid var(--line); padding-top:12px }
"""

_SHELL = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>{{ title }}</title><style>{{ css | safe }}</style></head><body>
  <div class="cover">
    <div class="kind">{{ kind_label }}</div>
    <h1>{{ cover_h1 }}</h1>
    <div class="sub">{{ cover_sub }}</div>
  </div>
  <div class="wrap">{{ body | safe }}</div>
</body></html>"""


def _shell(kind_label: str, title: str, cover_h1: str, cover_sub: str, body: str) -> str:
    css = _env.from_string(_CSS).render(kind_label=kind_label)
    return _env.from_string(_SHELL).render(
        css=css, kind_label=kind_label, title=title,
        cover_h1=cover_h1, cover_sub=cover_sub, body=body)


# ── findings (Vuln Research / Exploit Chain) ──────────────────────────────
_SEV = {"error": ("HIGH", "sev-high"), "warning": ("MEDIUM", "sev-med"), "note": ("LOW", "sev-low")}

_FINDINGS_BODY = """
<div class="meta">PROJECT: <code>{{ project_path }}</code></div>
<div class="summary">
  <div class="stat"><b>{{ confirmed }}</b><span>Confirmed</span></div>
  <div class="stat"><b>{{ partial }}</b><span>Partial</span></div>
  <div class="stat r"><b>{{ high }}</b><span>High severity</span></div>
  <div class="stat a"><b>{{ kev_count }}</b><span>CISA KEV-linked</span></div>
</div>
<p class="no">Cross-referenced to the MITRE graph (CWE·CAPEC·ATT&amp;CK·ATLAS·D3FEND·UKC) and intersected with NVD/CISA-KEV. Prioritize KEV-linked findings.</p>
{% for group, items in groups %}{% if items %}
<h2 class="section">{{ group }}</h2>
{% for f in items %}
<div class="card"><div class="head">
  <span class="badge {{ f.sev_class }}">{{ f.sev_label }}</span>
  <span class="loc">{{ f.file_path }}{% if f.line %}:{{ f.line }}{% endif %}</span>
  <span class="conf">conf {{ '%.2f'|format(f.confidence) }}</span>
  <span class="rule">{{ f.rule_source }}/{{ f.rule_id }}</span></div>
  <div class="body"><h3>{{ f.cwe_id }} — {{ f.cwe_name }}</h3><p class="msg">{{ f.message }}</p>
  <table class="x">
    {% if f.capecs %}<tr><th>CAPEC</th><td>{{ f.capecs|join(', ') }}</td></tr>{% endif %}
    {% if f.attacks %}<tr><th>ATT&amp;CK</th><td>{{ f.attacks|join(', ') }}</td></tr>{% endif %}
    {% if f.atlas %}<tr><th>ATLAS</th><td>{{ f.atlas|join(', ') }}</td></tr>{% endif %}
    {% if f.ukcs %}<tr><th>Kill chain</th><td>{{ f.ukcs|join(', ') }}</td></tr>{% endif %}
    {% if f.external %}<tr><th>Real-world</th><td class="kev">{{ f.external }}</td></tr>{% endif %}
    {% if f.d3fends %}<tr><th>Mitigations (D3FEND)</th><td>{{ f.d3fends|join(', ') }}</td></tr>{% endif %}
  </table></div></div>
{% endfor %}{% endif %}{% endfor %}
<div class="method"><b>Methodology.</b> Crossview's 5-stage pipeline surveys entry points and sinks, runs SAST + secrets/IaC/dependency scanners, walks each finding through the MITRE graph, scores priority against NVD/CISA-KEV, and verifies reachability before reporting. Confirmed = reachable from an entry point.</div>
"""


def render_findings_html(project_path: str, findings: list[dict], names: dict[str, str],
                         version: str = "0.1.0") -> str:
    items = []
    for f in findings:
        label, cls = _SEV.get(f.get("severity", "warning"), ("MEDIUM", "sev-med"))
        cwe = f.get("suspected_cwe") or ""
        ext = (f.get("evidence", {}) or {}).get("external_ref", "")
        items.append({**f, "sev_label": label, "sev_class": cls,
                      "cwe_id": cwe or "—", "cwe_name": names.get(cwe, ""),
                      "external": ext if ("KEV" in ext or "CVE" in ext) else ""})
    confirmed = [f for f in items if f["status"] == "confirmed"]
    partial = [f for f in items if f["status"] == "partial"]
    body = _env.from_string(_FINDINGS_BODY).render(
        project_path=project_path, confirmed=len(confirmed), partial=len(partial),
        high=sum(1 for f in items if f["sev_class"] == "sev-high"),
        kev_count=sum(1 for f in items if f["external"]),
        groups=[("Confirmed Findings", confirmed), ("Partial Findings", partial)])
    return _shell("Security Report", f"Crossview Security Report — {Path(project_path).name}",
                  "Crossview Security Report",
                  f"{Path(project_path).name} · {_now()} · Crossview {version}", body)


# backwards-compatible alias (the scan report stage imports render_html)
render_html = render_findings_html


# ── intel (OSCTI) ──────────────────────────────────────────────────────────
_INTEL_BODY = """
<div class="meta">SUBJECT: <code>{{ subject }}</code> &nbsp;·&nbsp; TYPE: <code>{{ rtype }}</code> &nbsp;·&nbsp; ORIGIN: <code>{{ origin }}</code></div>
<div class="summary">
  <div class="stat"><b>{{ refs|length }}</b><span>Cross-references</span></div>
  <div class="stat a"><b>{{ grounded }}</b><span>Grounded in silo</span></div>
</div>
{% if summary %}<h2 class="section">Strategic brief</h2><p>{{ summary }}</p>{% endif %}
{% if facts %}<h2 class="section">Key facts</h2><table class="x">
  {% for k,v in facts %}<tr><th>{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}
</table>{% endif %}
<h2 class="section">Grounded cross-references</h2>
<p class="no">Entities this report cites, resolved against Crossview's MITRE silo + enrichment.</p>
<table class="x"><tr><th>Entity</th><th>Source</th><th>Resolved</th><th>Name</th></tr>
{% for r in refs %}<tr><td><code>{{ r.entity_id }}</code></td><td>{{ r.entity_source }}</td>
  <td>{% if r.resolved %}<span class="ok">✓</span>{% else %}<span class="no">·</span>{% endif %}</td>
  <td>{{ r.name or '' }}</td></tr>{% endfor %}</table>
{% if sources %}<h2 class="section">Sources</h2><ul>{% for s in sources %}<li>{{ s }}</li>{% endfor %}</ul>{% endif %}
"""

_INTEL_FACT_FIELDS = [
    ("entityType", "Entity type"), ("subjectType", "Subject type"),
    ("firstSeen", "First seen"), ("lastSeen", "Last seen"), ("aliases", "Aliases"),
    ("toolType", "Tool type"), ("ttpEvolution", "TTP evolution"),
]


def render_intel_html(report: dict, refs: list[dict], version: str = "0.1.0") -> str:
    payload = report.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}
    facts = []
    for key, label in _INTEL_FACT_FIELDS:
        v = payload.get(key)
        if v:
            facts.append((label, ", ".join(v) if isinstance(v, list) else str(v)[:300]))
    cvss = payload.get("cvss") or {}
    if isinstance(cvss, dict) and cvss.get("baseScore"):
        facts.append(("CVSS", f"{cvss.get('baseScore')} ({cvss.get('severity', '')})"))
    kev = payload.get("cisaKEV") or {}
    if isinstance(kev, dict) and kev.get("inKEV"):
        facts.append(("CISA KEV", "in KEV — actively exploited"))
    sources = []
    for s in payload.get("groundingSources", []) or []:
        web = (s or {}).get("web") or {}
        if web.get("uri"):
            sources.append(f"{web.get('title') or ''} — {web['uri']}")
    body = _env.from_string(_INTEL_BODY).render(
        subject=report.get("subject", ""), rtype=report.get("report_type", ""),
        origin=report.get("origin", "intellio"), summary=report.get("summary", ""),
        facts=facts, refs=refs, grounded=sum(1 for r in refs if r.get("resolved")),
        sources=sources[:12])
    return _shell("Threat Intelligence Report",
                  f"Threat Intelligence — {report.get('subject', '')}",
                  report.get("subject", ""),
                  f"{report.get('report_type', '')} · {_now()} · Crossview {version}", body)


# ── artifact (Binary Analysis) — scaffold for the binary lens ─────────────
# Expected shape (filled by the future binary harness):
#   {"name","format","arch","hashes":{md5,sha256},"mitigations":{nx,pie,relro,canary},
#    "capabilities":[{"attack":"T1059","name":...}], "yara":[{"rule","family"}],
#    "iocs":[...], "cwes":[...]}
_ARTIFACT_BODY = """
<div class="meta">FILE: <code>{{ a.name }}</code> &nbsp;·&nbsp; {{ a.format }} / {{ a.arch }}</div>
{% if a.hashes %}<table class="x">{% for k,v in a.hashes.items() %}<tr><th>{{ k|upper }}</th><td><code>{{ v }}</code></td></tr>{% endfor %}</table>{% endif %}
{% if a.capabilities %}<h2 class="section">Capabilities → ATT&amp;CK</h2><table class="x"><tr><th>Technique</th><th>Capability</th></tr>
{% for c in a.capabilities %}<tr><td><code>{{ c.attack }}</code></td><td>{{ c.name }}</td></tr>{% endfor %}</table>{% endif %}
{% if a.yara %}<h2 class="section">YARA matches</h2><ul>{% for y in a.yara %}<li><code>{{ y.rule }}</code>{% if y.family %} — {{ y.family }}{% endif %}</li>{% endfor %}</ul>{% endif %}
{% if a.mitigations %}<h2 class="section">Hardening</h2><table class="x">{% for k,v in a.mitigations.items() %}<tr><th>{{ k|upper }}</th><td>{% if v %}<span class="ok">on</span>{% else %}<span class="kev">missing</span>{% endif %}</td></tr>{% endfor %}</table>{% endif %}
{% if a.iocs %}<h2 class="section">Indicators</h2><ul>{% for i in a.iocs %}<li><code>{{ i }}</code></li>{% endfor %}</ul>{% endif %}
"""


def render_artifact_html(artifact: dict, version: str = "0.1.0") -> str:
    body = _env.from_string(_ARTIFACT_BODY).render(a=artifact)
    return _shell("Binary Analysis Report",
                  f"Binary Analysis — {artifact.get('name', '')}",
                  artifact.get("name", ""),
                  f"{artifact.get('format', '')} · {_now()} · Crossview {version}", body)


# ── HTML → PDF (shared) ────────────────────────────────────────────────────

def html_to_pdf(html: str, pdf_path: Path) -> str | None:
    """Render HTML → PDF with the first available engine; return its name or None."""
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html).write_pdf(str(pdf_path))
        return "weasyprint"
    except Exception:
        pass
    try:
        _ensure_browser_env()
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(html, wait_until="networkidle")
            page.pdf(path=str(pdf_path), format="A4", print_background=True,
                     margin={"top": "16mm", "bottom": "18mm", "left": "14mm", "right": "14mm"})
            browser.close()
        return "chromium"
    except Exception:
        return None


def _ensure_browser_env() -> None:
    import glob
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        hits = sorted(glob.glob("/nix/store/*-playwright-browsers"))
        if hits:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = hits[-1]
    if "libstdc++" not in os.environ.get("LD_LIBRARY_PATH", ""):
        libs = sorted(glob.glob("/nix/store/*gcc*-lib/lib/libstdc++.so.6"))
        if libs:
            libdir = str(Path(libs[-1]).parent)
            os.environ["LD_LIBRARY_PATH"] = f"{libdir}:{os.environ.get('LD_LIBRARY_PATH', '')}".rstrip(":")
