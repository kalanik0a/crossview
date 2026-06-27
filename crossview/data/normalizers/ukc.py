"""Unified Kill Chain normalizer — emits the hardcoded UKC framework as Entities + xrefs."""
from crossview.domain import Entity, NormalizerResult, Xref
from crossview.kill_chain.ukc import PHASES, STAGES


def normalize() -> NormalizerResult:
    res = NormalizerResult(source_label="MITRE-adjacent · Unified Kill Chain (Pols)")

    # Stages first (3 top-level groupings)
    for stage_id, stage_name in STAGES:
        res.entities.append(
            Entity(
                id=stage_id,
                source="ukc",
                subtype="stage",
                name=stage_name,
                description=f"Unified Kill Chain stage: {stage_name}.",
            )
        )

    # 18 phases, each child of its stage
    for p in PHASES:
        res.entities.append(
            Entity(
                id=p.id,
                source="ukc",
                subtype="kill-chain-phase",
                name=p.name,
                description=p.description,
                raw={"order": p.order, "stage": p.stage},
            )
        )
        res.xrefs.append(
            Xref(
                src_id=p.id,
                dst_id=p.stage,
                relation="child_of",
                source="ukc",
            )
        )

    return res
