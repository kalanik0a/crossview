# 13 · Case Study — vulpy (anonymous HTTP → RCE)

A worked, end-to-end engagement that shows what Crossview is *for*: take a real, small,
intentionally-vulnerable app from GitHub, scan it, and turn a pile of SAST hits into one
**accessible exploit chain** — cross-referenced to MITRE, prioritized by real-world
exploitation, and fused with threat intel.

The full engagement (notes, evidence, intel, PoC, report, video) lives in
[examples/vulpy-engagement/](../examples/vulpy-engagement/README.md).

![case study — the exploit chain executing](../examples/vulpy-engagement/assets/flow-graph.gif)

<sub>▶ The exploit-chain flow graph from the cinematic case-study video. Data particles flow along each edge; the executing pulse lights the path anon HTTP → SQLi → admin → RCE. **Full video (internal media library):** `~/Videos/visionlighter/crossview/case-study/case-study.mp4`</sub>

> **Target:** [`fportantier/vulpy`](https://github.com/fportantier/vulpy) `bad/` — a deliberately-vulnerable Flask app. Authorized, local, educational.

## What Crossview found

`crossview scan target/bad` confirmed **15 vulnerabilities**, each verified reachable from
a live entrypoint and cross-referenced to CAPEC/ATT&CK/D3FEND/UKC with CISA-KEV signal:

| CWE | Weakness | Role in the chain |
|---|---|---|
| CWE-89 | SQL Injection (`libuser.py:12`) | pre-auth entry (A) |
| CWE-798 | Hard-coded Flask secret (`vulpy.py:16`) | pre-auth entry (B) |
| CWE-330 | Predictable API keys (`libapi.py:14`) | pre-auth entry (C) |
| CWE-94 | `debug=True` Werkzeug console (`vulpy.py:55`) | **RCE sink** |

## The chain

```text
anonymous HTTP ─▶ SQLi auth bypass (CWE-89)   ─┐
                  forged session (CWE-798)     ─┼─▶ authenticated ─▶ Werkzeug debugger ─▶ RCE
                  predictable API key (CWE-330) ─┘                    (CWE-94, debug=True)
```

Three independent pre-auth paths converge on an authenticated context; `debug=True` turns
that into code execution. Full analysis: [exploit-chain.md](../examples/vulpy-engagement/research/exploit-chain.md)
· knowledge graph: [exploit-chain.canvas](../examples/vulpy-engagement/research/exploit-chain.canvas).

## Why a linter wouldn't have found *this*

A SAST tool says "possible SQL injection." Crossview adds the three things that turn a
finding into a finding *that matters*:

1. **Reachability** — verify re-surveyed the live code and confirmed each sink sits on an
   unauthenticated path (confidence 1.00).
2. **Cross-reference** — every CWE resolved to its CAPEC/ATT&CK/D3FEND, so isolated bugs
   became a linkable graph and the chain emerged.
3. **Real-world prioritization** — `enrich` intersected the CWEs with CISA KEV, which
   re-ranked CWE-94 to the top (**65 exploited CVEs, 9 ransomware**) over noisier hits.

![CISA KEV exploitation ticker for CWE-94](../examples/vulpy-engagement/assets/kev-ticker.gif)
4. **Intel fusion** — `intel generate` attached grounded threat reports to the same CWE
   nodes (see the [Intel Mindmeld](12-intel-mindmeld.md)).

## The research trail

The engagement is presented as an iterative researcher would build it:

- [research/journal.md](../examples/vulpy-engagement/research/journal.md) — 5 sessions: survey → triage → chain-hunt → intel → write-up.
- [research/crossview-evidence.md](../examples/vulpy-engagement/research/crossview-evidence.md) — captured `show`/`enrich` output.
- [research/intel/](../examples/vulpy-engagement/research/intel/) — grounded intel reports.
- [research/poc/exploit_chain.py](../examples/vulpy-engagement/research/poc/exploit_chain.py) — ethical local PoC (Stages 1–2).
- [report/case-study.md](../examples/vulpy-engagement/report/case-study.md) — the client-grade assessment.
- **Case-study video** (`~/Videos/visionlighter/crossview/case-study/case-study.mp4`, internal media library) — a ~70-second **cinematic** walkthrough: a code-scan beam tagging sink lines, an animated 15-finding matrix with a live counter, the exploit-chain **flow graph** with flowing data particles and an executing pulse, and a scrolling **CISA-KEV exploitation ticker** (65 exploited / 9 ransomware) — over the Crossview music bed. Previewed by the GIFs above; regenerate with `python3 assets/build_cinematic.py`.

## Reproduce it

```bash
cd examples/vulpy-engagement
./fetch-target.sh
crossview scan target/bad
crossview enrich CWE-94
crossview intel generate CWE-89
```
