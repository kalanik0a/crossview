"""STIX 2.x normalizer — handles CAPEC, ATT&CK (Enterprise/Mobile/ICS), and ATLAS.

All four sources share the same STIX bundle shape:
  {type: "bundle", objects: [{type: "attack-pattern" | "x-mitre-tactic" | ...}, ...]}

We extract canonical IDs (CAPEC-66, T1059, AML.T0051, M1xxx) from
external_references[] and normalize relationships into our unified xref vocab.
"""

from crossview.data.normalizers.base import first_external_id, safe_text
from crossview.domain import Entity, NormalizerResult, Xref
from crossview.kill_chain.ukc import ATTACK_TACTIC_TO_UKC

# How each source identifies itself in external_references[].source_name
EXTERNAL_SOURCE_NAME = {
    "capec": "capec",
    "attack": "mitre-attack",
    "atlas": "mitre-atlas",
}


# STIX relationship_type → our unified relation vocabulary.
# Anything not mapped is dropped (with a note).
RELATION_MAP = {
    "subtechnique-of":  "child_of",
    "mitigates":        "mitigates",
    "revoked-by":       "related",   # admin metadata; treat as weak link
    # Skip for v1: "uses" (threat-actor edges), "detects" (data-source edges),
    # "attributed-to", "targets" (campaign metadata).
}

# STIX object types we actually normalize into Entity rows.
# Relationships with endpoints outside this set are dropped (e.g. group→group).
NORMALIZED_TYPES = {
    "attack-pattern",
    "x-mitre-tactic",
    "course-of-action",
    "x-mitre-matrix",
    "x-mitre-asset",
}


def _canonical_id(obj: dict, source: str) -> str | None:
    src_name = EXTERNAL_SOURCE_NAME.get(source)
    if not src_name:
        return None
    return first_external_id(obj.get("external_references", []), src_name)


def _normalize_attack_pattern(
    obj: dict,
    source: str,
    framework: str | None,
    tactic_by_phase: dict[str, str] | None = None,
) -> tuple[Entity, list[Xref]]:
    canonical = _canonical_id(obj, source)
    if not canonical:
        return None, []  # skip patterns without a canonical ID

    subtype = "attack-pattern" if source == "capec" else "technique"
    abstraction = obj.get("x_capec_abstraction") if source == "capec" else None

    ent = Entity(
        id=canonical,
        source=source,
        subtype=subtype,
        name=safe_text(obj.get("name")),
        description=safe_text(obj.get("description")),
        framework=framework,
        abstraction=abstraction,
        stix_id=obj.get("id"),
        created_at=obj.get("created"),
        modified_at=obj.get("modified"),
        raw=obj,
    )

    xrefs: list[Xref] = []
    # CAPEC's external_references include CWE-XX and ATT&CK T-XXXX co-targets.
    # ATT&CK's include CAPEC-XX. ATLAS may include ATT&CK references.
    for r in obj.get("external_references", []):
        sn = r.get("source_name")
        ext = r.get("external_id")
        if not ext:
            continue
        if sn == "cwe" and ext != canonical:
            xrefs.append(Xref(canonical, ext, "uses_weakness", source))
        elif sn == "capec" and ext != canonical and ext.startswith("CAPEC-"):
            xrefs.append(Xref(canonical, ext, "related", source))
        elif sn in ("ATTACK", "mitre-attack") and ext != canonical:
            xrefs.append(Xref(canonical, ext, "related", source))
        elif sn == "mitre-atlas" and ext != canonical:
            xrefs.append(Xref(canonical, ext, "related", source))

    # CAPEC has explicit child/precede via x_capec_*_refs (STIX UUIDs, resolved later)
    for ref in obj.get("x_capec_child_of_refs", []) or []:
        xrefs.append(Xref(obj["id"], ref, "child_of", source, metadata={"_unresolved": True}))
    for ref in obj.get("x_capec_can_precede_refs", []) or []:
        xrefs.append(Xref(obj["id"], ref, "chains_to", source, metadata={"_unresolved": True}))
    for ref in obj.get("x_capec_can_follow_refs", []) or []:
        xrefs.append(Xref(ref, obj["id"], "chains_to", source, metadata={"_unresolved": True}))
    for ref in obj.get("x_capec_peer_of_refs", []) or []:
        xrefs.append(Xref(obj["id"], ref, "related", source, metadata={"_unresolved": True}))

    # kill_chain_phases → both the in-source tactic AND the UKC phase
    for kcp in obj.get("kill_chain_phases", []) or []:
        phase = kcp.get("phase_name", "").lower()
        # 1. Link technique → tactic in this source
        if tactic_by_phase:
            tactic_id = tactic_by_phase.get(phase)
            if tactic_id:
                xrefs.append(Xref(canonical, tactic_id, "kill_chain_phase", source))
        # 2. Bridge to UKC
        ukc_id = ATTACK_TACTIC_TO_UKC.get(phase)
        if ukc_id:
            xrefs.append(
                Xref(canonical, ukc_id, "kill_chain_phase", source, metadata={"tactic": phase})
            )

    return ent, xrefs


def _normalize_tactic(obj: dict, source: str, framework: str | None) -> Entity | None:
    canonical = _canonical_id(obj, source)
    if not canonical:
        # Some matrices use shortname-derived IDs; fall back to short name
        canonical = obj.get("x_mitre_shortname")
        if not canonical:
            return None
        canonical = canonical.upper().replace("-", "_")

    return Entity(
        id=canonical,
        source=source,
        subtype="tactic",
        name=safe_text(obj.get("name")),
        description=safe_text(obj.get("description")),
        framework=framework,
        stix_id=obj.get("id"),
        created_at=obj.get("created"),
        modified_at=obj.get("modified"),
        raw=obj,
    )


def _normalize_mitigation(
    obj: dict, source: str, framework: str | None
) -> Entity | None:
    canonical = _canonical_id(obj, source)
    if not canonical:
        return None
    return Entity(
        id=canonical,
        source=source,
        subtype="mitigation",
        name=safe_text(obj.get("name")),
        description=safe_text(obj.get("description")),
        framework=framework,
        stix_id=obj.get("id"),
        created_at=obj.get("created"),
        modified_at=obj.get("modified"),
        raw=obj,
    )


def _normalize_matrix(obj: dict, source: str, framework: str | None) -> Entity | None:
    canonical = _canonical_id(obj, source) or obj.get("x_mitre_shortname") or framework
    if not canonical:
        return None
    return Entity(
        id=f"{source}:matrix:{canonical}",
        source=source,
        subtype="matrix",
        name=safe_text(obj.get("name")),
        description=safe_text(obj.get("description")),
        framework=framework,
        stix_id=obj.get("id"),
        raw=obj,
    )


def _normalize_asset(obj: dict, source: str, framework: str | None) -> Entity | None:
    canonical = _canonical_id(obj, source) or obj.get("name", "").replace(" ", "_")
    if not canonical:
        return None
    return Entity(
        id=f"{source}:asset:{canonical}",
        source=source,
        subtype="asset",
        name=safe_text(obj.get("name")),
        description=safe_text(obj.get("description")),
        framework=framework,
        stix_id=obj.get("id"),
        raw=obj,
    )


def _resolve_relationship(
    rel_obj: dict, by_stix_id: dict[str, dict], source: str
) -> Xref | None:
    """Convert a STIX relationship object into our Xref using internal IDs."""
    rt = rel_obj.get("relationship_type")
    relation = RELATION_MAP.get(rt)
    if not relation:
        return None
    src = by_stix_id.get(rel_obj.get("source_ref"))
    dst = by_stix_id.get(rel_obj.get("target_ref"))
    if not src or not dst:
        return None
    if src.get("type") not in NORMALIZED_TYPES or dst.get("type") not in NORMALIZED_TYPES:
        return None
    src_id = _canonical_id(src, source)
    dst_id = _canonical_id(dst, source)
    if not src_id or not dst_id:
        return None
    return Xref(src_id, dst_id, relation, source)


def normalize(bundle: dict, source: str, framework: str | None = None) -> NormalizerResult:
    """Walk a STIX bundle and emit Entity + Xref records."""
    res = NormalizerResult(source_label=f"{source}/{framework or 'main'}")
    objects: list[dict] = bundle.get("objects", [])
    by_stix_id: dict[str, dict] = {o["id"]: o for o in objects if "id" in o}

    # Pre-index tactics by their phase short-name, so we can link
    # technique → tactic via kill_chain_phases[].phase_name during the entity pass.
    tactic_by_phase: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = (obj.get("x_mitre_shortname") or "").lower()
            tactic_id = _canonical_id(obj, source)
            if shortname and tactic_id:
                tactic_by_phase[shortname] = tactic_id

    # First pass: entities
    for obj in objects:
        t = obj.get("type")
        if t == "attack-pattern":
            ent, xrefs = _normalize_attack_pattern(obj, source, framework, tactic_by_phase)
            if ent:
                res.entities.append(ent)
                res.xrefs.extend(xrefs)
        elif t == "x-mitre-tactic":
            ent = _normalize_tactic(obj, source, framework)
            if ent:
                res.entities.append(ent)
        elif t == "course-of-action":
            ent = _normalize_mitigation(obj, source, framework)
            if ent:
                res.entities.append(ent)
        elif t == "x-mitre-matrix":
            ent = _normalize_matrix(obj, source, framework)
            if ent:
                res.entities.append(ent)
        elif t == "x-mitre-asset":
            ent = _normalize_asset(obj, source, framework)
            if ent:
                res.entities.append(ent)

    # Second pass: relationships
    for obj in objects:
        if obj.get("type") == "relationship":
            xref = _resolve_relationship(obj, by_stix_id, source)
            if xref:
                res.xrefs.append(xref)

    # Third pass: resolve unresolved STIX-UUID xrefs (CAPEC's x_capec_*_refs)
    res.xrefs = _resolve_stix_uuid_xrefs(res.xrefs, by_stix_id, source)

    return res


def _resolve_stix_uuid_xrefs(
    xrefs: list[Xref], by_stix_id: dict[str, dict], source: str
) -> list[Xref]:
    out: list[Xref] = []
    for x in xrefs:
        if not x.metadata.get("_unresolved"):
            out.append(x)
            continue
        # src or dst is still a STIX UUID; look up canonical IDs
        src_obj = by_stix_id.get(x.src_id) if x.src_id.startswith("attack-pattern--") else None
        dst_obj = by_stix_id.get(x.dst_id) if x.dst_id.startswith("attack-pattern--") else None
        src_id = _canonical_id(src_obj, source) if src_obj else x.src_id
        dst_id = _canonical_id(dst_obj, source) if dst_obj else x.dst_id
        if src_id and dst_id and not src_id.startswith("attack-pattern--") and not dst_id.startswith("attack-pattern--"):
            out.append(Xref(src_id, dst_id, x.relation, x.source))
    return out
