"""Unified entity and cross-reference shapes.

Every normalizer produces these. Every consumer (DB, GraphQL, scanner, TUI)
reads these. Source-specific quirks live in `raw` for fidelity, never in the
public surface.
"""
from dataclasses import dataclass, field
from typing import Literal

# ---- Vocabularies (closed sets) ---------------------------------------------

Source = Literal["cwe", "capec", "attack", "atlas", "d3fend", "ukc"]

Subtype = Literal[
    "weakness",         # CWE
    "category",         # CWE category (groups weaknesses)
    "view",             # CWE view (e.g. CWE-1000)
    "attack-pattern",   # CAPEC
    "technique",        # ATT&CK / ATLAS
    "tactic",           # ATT&CK / ATLAS
    "matrix",           # ATT&CK / ATLAS
    "mitigation",       # CAPEC course-of-action, ATT&CK course-of-action, ATLAS, D3FEND defense
    "asset",            # ATT&CK ICS x-mitre-asset
    "kill-chain-phase", # UKC
    "stage",            # UKC top-level: in / through / out
]

Relation = Literal[
    "child_of",          # hierarchy
    "chains_to",         # CAPEC CanPrecede, attack chain
    "related",           # generic peer relationship
    "mitigates",         # mitigation → technique/weakness
    "counters",          # D3FEND defense → ATT&CK technique
    "targets",           # weakness → attack-pattern, attack-pattern → asset
    "uses_weakness",     # CAPEC → CWE
    "kill_chain_phase",  # technique → UKC phase / ATT&CK tactic
]


# ---- Polyfill records --------------------------------------------------------

@dataclass(frozen=True)
class Entity:
    """One canonical security knowledge entity, source-agnostic."""

    id: str                  # canonical: "CWE-89", "CAPEC-66", "T1059", "AML.T0051", "D3-CH", "UKC-7"
    source: str              # see Source
    subtype: str             # see Subtype
    name: str
    description: str = ""
    framework: str | None = None       # "enterprise" | "mobile" | "ics" for ATT&CK; "atlas" for ATLAS
    abstraction: str | None = None     # CAPEC: Standard|Detailed|Meta; CWE: variant|class|base
    stix_id: str | None = None          # internal STIX uuid for relationship resolution
    created_at: str | None = None
    modified_at: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Xref:
    """One directed edge between two entities."""

    src_id: str
    dst_id: str
    relation: str            # see Relation
    source: str              # which dataset asserted this edge
    metadata: dict = field(default_factory=dict)


@dataclass
class NormalizerResult:
    """What every normalizer returns. Loader writes these to the DB."""

    entities: list[Entity] = field(default_factory=list)
    xrefs: list[Xref] = field(default_factory=list)
    source_label: str = ""
    notes: list[str] = field(default_factory=list)  # warnings, skipped items, etc.

    def extend(self, other: "NormalizerResult") -> None:
        self.entities.extend(other.entities)
        self.xrefs.extend(other.xrefs)
        self.notes.extend(other.notes)
