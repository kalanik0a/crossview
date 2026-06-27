"""GraphQL types — code-first via Strawberry.

Maps 1:1 to the polyfill domain types. Same field shapes; same source-agnostic
contract. Every consumer (CLI, TUI, scanner, future Claude plugin) reads
through this single schema.
"""
from __future__ import annotations

from typing import Optional

import strawberry


@strawberry.type
class Entity:
    id: str
    source: str
    subtype: str
    name: str
    description: str
    framework: Optional[str]
    abstraction: Optional[str]
    stix_id: Optional[str]


@strawberry.type
class Xref:
    src_id: str
    dst_id: str
    relation: str
    source: str


@strawberry.type
class CVE:
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    published_at: Optional[str]
    in_kev: bool


@strawberry.type
class KEVRow:
    cve_id: str
    vendor_project: Optional[str]
    product: Optional[str]
    vulnerability_name: Optional[str]
    date_added: Optional[str]
    short_description: Optional[str]
    known_ransomware_use: Optional[str]


@strawberry.type
class ExploitChain:
    """Aggregated cross-source view rooted at a CWE.

    Returning all chain limbs as a single object lets a single GraphQL query
    fan out across CWE → CAPEC → ATT&CK → ATLAS → D3FEND → UKC.
    """
    cwe_id: str
    parent_cwes: list[str]
    capecs: list[str]
    attack_techniques: list[str]
    atlas_techniques: list[str]
    d3fend_techniques: list[str]
    ukc_phases: list[str]


@strawberry.type
class Hypothesis:
    id: int
    investigation_id: int
    parent_id: Optional[int]
    statement: str
    confidence: float
    suspected_cwe: Optional[str]
    suspected_capec: Optional[str]
    suspected_attack: Optional[str]
    suspected_atlas: Optional[str]
    status: str
    posted_at: str


@strawberry.type
class Investigation:
    id: int
    project_path: str
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    summary: str
    status: str
    opened_at: str


@strawberry.type
class Evidence:
    id: int
    hypothesis_id: int
    kind: str
    content: str
    file_path: Optional[str]
    line: Optional[int]
    ref_url: Optional[str]
    created_at: str


@strawberry.type
class Validation:
    id: int
    hypothesis_id: int
    entity_type: str
    entity_id: str
    match: str
    notes: Optional[str]
    created_at: str
