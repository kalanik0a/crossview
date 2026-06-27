"""CWE XML normalizer — converts cwec.xml into Entity + Xref records.

Uses xmltodict to flatten the XML into nested dicts, then walks Weaknesses,
Categories, and Views. Cross-references to CAPEC and ATT&CK come from
Related_Attack_Patterns.
"""
from pathlib import Path

import xmltodict

from crossview.data.normalizers.base import safe_text
from crossview.domain import Entity, NormalizerResult, Xref


def _as_list(v) -> list:
    """xmltodict yields a single dict for a single child, list for multiple. Normalize."""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _description_text(weakness: dict) -> str:
    parts = [
        safe_text(weakness.get("Description", "")),
        safe_text(weakness.get("Extended_Description", "")),
    ]
    return "\n\n".join(p for p in parts if p)


def _normalize_weakness(w: dict) -> tuple[Entity, list[Xref]]:
    cwe_id = f"CWE-{w['@ID']}"
    ent = Entity(
        id=cwe_id,
        source="cwe",
        subtype="weakness",
        name=safe_text(w.get("@Name", "")),
        description=_description_text(w),
        abstraction=w.get("@Abstraction"),
        raw=w,
    )

    xrefs: list[Xref] = []

    # Related_Weaknesses → child_of / related
    for rel in _as_list((w.get("Related_Weaknesses") or {}).get("Related_Weakness")):
        target = f"CWE-{rel['@CWE_ID']}"
        nature = rel.get("@Nature", "Related").lower()
        if nature == "childof":
            xrefs.append(Xref(cwe_id, target, "child_of", "cwe"))
        elif nature == "peerof" or nature == "canalsobe":
            xrefs.append(Xref(cwe_id, target, "related", "cwe"))
        elif nature == "canprecede" or nature == "canfollow":
            xrefs.append(Xref(cwe_id, target, "chains_to", "cwe"))
        else:
            xrefs.append(Xref(cwe_id, target, "related", "cwe", metadata={"nature": nature}))

    # Related_Attack_Patterns → CAPEC link (relation: targets — "this CWE is targeted by CAPEC-X")
    rap = (w.get("Related_Attack_Patterns") or {}).get("Related_Attack_Pattern")
    for ap in _as_list(rap):
        target = f"CAPEC-{ap['@CAPEC_ID']}"
        xrefs.append(Xref(cwe_id, target, "targets", "cwe"))

    return ent, xrefs


def _normalize_category(c: dict) -> Entity:
    return Entity(
        id=f"CWE-{c['@ID']}",
        source="cwe",
        subtype="category",
        name=safe_text(c.get("@Name", "")),
        description=safe_text((c.get("Summary") or "")),
        raw=c,
    )


def _normalize_view(v: dict) -> Entity:
    return Entity(
        id=f"CWE-{v['@ID']}",
        source="cwe",
        subtype="view",
        name=safe_text(v.get("@Name", "")),
        description=safe_text((v.get("Objective") or "")),
        raw=v,
    )


def normalize_file(xml_path: Path) -> NormalizerResult:
    res = NormalizerResult(source_label="MITRE CWE")
    with xml_path.open("rb") as f:
        doc = xmltodict.parse(f, dict_constructor=dict)

    catalog = doc.get("Weakness_Catalog", {})

    weaknesses = (catalog.get("Weaknesses") or {}).get("Weakness")
    for w in _as_list(weaknesses):
        ent, xrefs = _normalize_weakness(w)
        res.entities.append(ent)
        res.xrefs.extend(xrefs)

    categories = (catalog.get("Categories") or {}).get("Category")
    for c in _as_list(categories):
        res.entities.append(_normalize_category(c))

    views = (catalog.get("Views") or {}).get("View")
    for v in _as_list(views):
        res.entities.append(_normalize_view(v))

    return res
