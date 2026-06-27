"""In-process intel report generation — Intellio's Gemini-grounded generators
ported to Python. Produces an Intellio-shaped report dict for a subject, which
the intel layer then grounds + persists into the Crossview silo.

Faithful to Intellio's ReportService: same classification heuristics, the same
per-type prompts, and the same Google-Search grounding tool. Structured output
is driven by the prompt (which enumerates the required fields) and a lenient
JSON parse, which is robust across Gemini models when the grounding tool is on.

Needs GEMINI_API_KEY (or GOOGLE_API_KEY). Network to Google AI required.
"""
from __future__ import annotations

import json
import os
import re

import httpx

# Intellio's configured models, with fallbacks if a preview model is unavailable.
REPORT_MODELS = ["gemini-3-pro-preview", "gemini-2.5-flash", "gemini-2.0-flash"]
VALID_CLASSES = ("threat-intel", "red-team-tool", "blue-team-tool",
                 "engineering", "vulnerability")

# ── classification (ported from ReportService.GuessClassification) ──
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_CWE = re.compile(r"^CWE-\d{1,6}$", re.I)
_CPE = re.compile(r"^cpe:2\.3:", re.I)
_TECH = re.compile(r"^T\d{4}(\.\d{3})?$", re.I)
_ENGINEERING = ("nist", "iso", "pci", "cis", "framework", "standard",
                "architecture", "reference architecture", "zero trust")
_RED = ("red team", "offensive", "exploit", "payload", "c2", "post-exploitation",
        "lateral movement", "privilege escalation")
_BLUE = ("blue team", "defensive", "siem", "edr", "xdr", "soar", "soc", "ids",
         "ips", "waf", "detection", "forensics")


def classify(subject: str) -> str:
    s = subject.strip()
    if _CVE.match(s) or _CWE.match(s) or _CPE.match(s) or _TECH.match(s):
        return "vulnerability"
    low = s.lower()
    if any(k in low for k in _ENGINEERING):
        return "engineering"
    if any(k in low for k in _RED):
        return "red-team-tool"
    if any(k in low for k in _BLUE):
        return "blue-team-tool"
    return "threat-intel"


# ── prompts (verbatim from Intellio's ReportService) ──

def _p_vulnerability(s: str) -> str:
    return f'''You are a cybersecurity vulnerability researcher. Your task is to compile a detailed report on a given CVE, CWE, or CPE. Use your search capabilities to gather information from authoritative sources.

The subject to research is: "{s}"

Generate a response exclusively as a single JSON object. Do not add any explanatory text.

The report must contain: subjectName, subjectType (CVE|CWE|CPE), description, cvss {{version, baseScore, vectorString, severity}}, officialReferences[], cisaKEV {{inKEV, dateAdded, dueDate, notes, url}}, exploitability[] (Exploit-DB, Metasploit module names, GitHub PoC repos, Google Hacking DB dorks), relatedLOLBIN, documentation[], chainAnalysis[] (for CPE: major CVEs + top 3 CWEs; for CVE: the CWE category; for CWE: 3 recent high-impact CVEs). Each chainAnalysis entry is {{id, type (CVE|CWE|CPE), description}}.'''


def _p_engineering(s: str) -> str:
    return f'''You are a cybersecurity architect and standards expert. Research a given cybersecurity standard, architecture, or framework and compile a detailed report. Use your search capabilities to find authoritative information from official sources (NIST, IETF, ISO, DoD), industry bodies (CIS, FIRST), and reputable educational platforms.

The subject to research is: "{s}"

Generate a response exclusively as a single JSON object. No text before or after.

The report must contain: subjectName, aliases[], subjectType, strategicBrief {{summary}}, timelineHistory[], referencedStandards[], implementationGuides[], nextGenArchitectures[], bodiesOfKnowledge[].'''


def _p_red(s: str) -> str:
    return f'''You are a Red Teaming specialist. Research a given cybersecurity tool and compile a detailed report from the perspective of an offensive security professional. Use your search capabilities to find the most relevant public information from trusted sources.

The subject to research is: "{s}"

Generate a response exclusively as a single JSON object. No text before or after.

The report must contain: subjectName, aliases[], toolType, capabilities[], strategicBrief {{summary}}, publications[], repositories[].'''


def _p_blue(s: str) -> str:
    return f'''You are a Blue Teaming specialist. Research a given cybersecurity tool and compile a detailed report from a defensive perspective. Use your search capabilities to find the most relevant public information.

The subject to research is: "{s}"

Generate a response exclusively as a single JSON object. No text before or after.

The report must contain: subjectName, aliases[], toolType, capabilities[], strategicBrief {{summary}}, publications[], repositories[], educationalResources[].'''


def _p_threat(s: str) -> str:
    return f'''You are a world-class Cyber Threat Intelligence Analyst. Research a given subject (malware family, threat actor, or APT group) and compile a detailed report. Use your search capabilities to find the most recent and relevant public information from trusted sources (security vendor blogs, cybersecurity news, government advisories).

The subject to research is identified by the following names and aliases: "{s}"

Generate a response exclusively as a single JSON object. No text before or after.

The report must contain: subjectName, aliases[], entityType (Malware|Threat Actor|APT|Unknown), firstSeen, lastSeen, confidence {{score, justification}}, historicalCampaigns[], mostProfoundReport {{title, url, source, summary}}, timeline[] (date, event, sourceUrl), recentReports[], mitreAttackTechniques[] (id like T1059, name, url), associatedIOCs[], ttpEvolution, keyBehavioralChanges[], externalLinks[], exportData {{stixPattern, sigmaRule, yaraExplanation}}.'''


PROMPTS = {
    "vulnerability": _p_vulnerability,
    "engineering": _p_engineering,
    "red-team-tool": _p_red,
    "blue-team-tool": _p_blue,
    "threat-intel": _p_threat,
}


# ── Gemini call (grounded) ──

def _gemini_grounded(prompt: str, api_key: str, models: list[str]) -> dict:
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "tools": [{"google_search": {}}],
    }
    last_err = None
    for model in models:
        # [CWE-598] API key in header, not URL query string
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model}:generateContent")
        try:
            r = httpx.post(url, json=body, timeout=180, headers={"x-goog-api-key": api_key})
        except httpx.HTTPError as e:  # network-level
            last_err = e
            continue
        if r.status_code == 200:
            return r.json()
        last_err = RuntimeError(f"{model}: HTTP {r.status_code} {r.text[:200]}")
        if r.status_code in (400, 403, 404):
            continue                      # try the next fallback model
        r.raise_for_status()
    raise RuntimeError(f"Gemini generation failed: {last_err}")


def _extract(resp: dict) -> tuple[str, list[dict]]:
    cands = resp.get("candidates") or []
    if not cands:
        raise RuntimeError("Gemini returned no candidates.")
    cand = cands[0]
    text = "".join(p.get("text", "")
                   for p in cand.get("content", {}).get("parts", []))
    gm = cand.get("groundingMetadata", {})
    sources = [{"web": {"uri": c["web"].get("uri"), "title": c["web"].get("title")}}
               for c in gm.get("groundingChunks", []) if c.get("web")]
    return text, sources


def _parse_json(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t).rstrip("`").rstrip()
    a, b = t.find("{"), t.rfind("}")
    if a == -1 or b == -1:
        raise RuntimeError(f"No JSON object in model output: {text[:200]}")
    return json.loads(t[a:b + 1])


def generate(subject: str, classification: str | None = None,
             api_key: str | None = None, model: str | None = None) -> dict:
    """Generate an Intellio-shaped report dict for `subject` via Gemini grounding."""
    api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise SystemExit("Set GEMINI_API_KEY or GOOGLE_API_KEY, or pass api_key.")
    cls = classification or classify(subject)
    if cls not in VALID_CLASSES:
        cls = "threat-intel"
    models = ([model] + REPORT_MODELS) if model else REPORT_MODELS
    resp = _gemini_grounded(PROMPTS[cls](subject), api_key, models)
    text, sources = _extract(resp)
    report = _parse_json(text)
    report["reportType"] = cls
    report.setdefault("subjectName", subject)
    report["groundingSources"] = sources
    return report
