"""D3FEND normalizer.

Two inputs:
  1. d3fend-ontology.json (JSON-LD with @graph) — source of D3FEND techniques
  2. d3fend-mappings.json (SPARQL JSON results)  — D3FEND ↔ ATT&CK xrefs

For v1 we keep this pragmatic: extract NamedIndividuals with d3f:* types
that look like defensive techniques, derive a stable D3-XX style id from the
URI fragment, and walk the SPARQL bindings to build counters-edges.
"""
import json
import re
from pathlib import Path

from crossview.data.normalizers.base import safe_text
from crossview.domain import Entity, NormalizerResult, Xref

D3FEND_ID_FROM_URI = re.compile(r"#([A-Za-z][A-Za-z0-9_-]+)$")
ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _extract_id(uri: str) -> str | None:
    m = D3FEND_ID_FROM_URI.search(uri)
    if not m:
        return None
    fragment = m.group(1)
    # Defensive techniques in D3FEND look like CamelCase fragments;
    # we keep them prefixed so canonical IDs don't collide with anything else.
    return f"D3F:{fragment}"


def _label_of(node: dict) -> str:
    label = node.get("rdfs:label") or node.get("label")
    if isinstance(label, dict):
        return safe_text(label.get("@value") or label.get("value"))
    if isinstance(label, list) and label:
        return safe_text(label[0])
    return safe_text(label)


def _is_defensive_technique(node: dict) -> bool:
    types = node.get("@type") or []
    if isinstance(types, str):
        types = [types]
    # Defensive techniques tend to have d3f:DefensiveTechnique or be subclasses
    type_str = "|".join(types)
    return "d3f:DefensiveTechnique" in type_str or "DefensiveTechnique" in type_str


def normalize_ontology(path: Path) -> NormalizerResult:
    res = NormalizerResult(source_label="MITRE D3FEND ontology")
    data = json.loads(path.read_text())
    graph = data.get("@graph") or []

    seen: set[str] = set()
    for node in graph:
        if not isinstance(node, dict):
            continue
        uri = node.get("@id", "")
        if not uri:
            continue
        cid = _extract_id(uri)
        if not cid or cid in seen:
            continue

        types = node.get("@type") or []
        if isinstance(types, str):
            types = [types]
        type_str = "|".join(str(t) for t in types)

        if _is_defensive_technique(node):
            seen.add(cid)
            res.entities.append(
                Entity(
                    id=cid,
                    source="d3fend",
                    subtype="technique",
                    name=_label_of(node) or cid,
                    description=safe_text(node.get("rdfs:comment") or node.get("d3f:definition")),
                    raw=node,
                )
            )
        elif "ATTACKEnterpriseMitigation" in type_str:
            # Bridge nodes — D3FEND knows about ATT&CK mitigation Mxxxx; we already get those from ATT&CK.
            continue

    return res


def normalize_mappings(path: Path) -> NormalizerResult:
    """Walk SPARQL bindings → emit D3F:* ↔ T* xrefs (counters)."""
    res = NormalizerResult(source_label="MITRE D3FEND mappings")
    data = json.loads(path.read_text())
    bindings = (data.get("results") or {}).get("bindings") or []

    seen_pairs: set[tuple[str, str]] = set()
    seen_techs: set[str] = set()

    for b in bindings:
        def_label = (b.get("def_tech_label") or {}).get("value") or ""
        off_id_raw = (b.get("off_tech_id") or {}).get("value") or ""
        off_tech_label = (b.get("off_tech_label") or {}).get("value") or ""
        def_tactic_label = (b.get("def_tactic_label") or {}).get("value") or ""

        if not def_label:
            continue

        # Synthesize D3F id from label (CamelCase)
        d3f_id = f"D3F:{def_label.replace(' ', '_')}"

        # Register the defensive technique once
        if d3f_id not in seen_techs:
            seen_techs.add(d3f_id)
            res.entities.append(
                Entity(
                    id=d3f_id,
                    source="d3fend",
                    subtype="technique",
                    name=def_label,
                    description=f"D3FEND defensive technique. Tactic: {def_tactic_label or 'unknown'}.",
                    raw=b,
                )
            )

        # Extract canonical ATT&CK id from URI or label
        att_id_match = ATTACK_ID_RE.search(off_id_raw) or ATTACK_ID_RE.search(off_tech_label)
        if not att_id_match:
            continue
        att_id = att_id_match.group(1)

        pair = (d3f_id, att_id)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        res.xrefs.append(
            Xref(
                src_id=d3f_id,
                dst_id=att_id,
                relation="counters",
                source="d3fend",
                metadata={
                    "def_tactic": def_tactic_label,
                    "def_artifact": (b.get("def_artifact_label") or {}).get("value"),
                    "off_artifact": (b.get("off_artifact_label") or {}).get("value"),
                },
            )
        )

    res.notes.append(f"emitted {len(seen_techs)} D3FEND techniques, {len(seen_pairs)} counters-edges")
    return res
