"""Strawberry schema assembly. Code-first, in-process by default."""
from __future__ import annotations

from typing import Optional

import strawberry

from crossview.graph.resolvers import cohort, entity, exploit_chain
from crossview.graph.types import (
    CVE,
    Entity,
    Evidence,
    ExploitChain,
    Hypothesis,
    Investigation,
    KEVRow,
    Validation,
    Xref,
)


@strawberry.type
class Query:
    # ─── Reference silo ───────────────────────────────────────────────────
    @strawberry.field
    def entity(self, id: str) -> Optional[Entity]:
        return entity.resolve_entity(id)

    @strawberry.field
    def search(self, query: str, limit: int = 20) -> list[Entity]:
        return entity.resolve_search(query, limit=limit)

    @strawberry.field
    def entities_by_source(
        self,
        source: str,
        subtype: Optional[str] = None,
        limit: int = 100,
    ) -> list[Entity]:
        return entity.resolve_entities_by_source(source, subtype, limit)

    @strawberry.field
    def xrefs_out(self, entity_id: str) -> list[Xref]:
        return entity.resolve_xrefs_outbound(entity_id)

    @strawberry.field
    def xrefs_in(self, entity_id: str) -> list[Xref]:
        return entity.resolve_xrefs_inbound(entity_id)

    # ─── Cross-source chain ───────────────────────────────────────────────
    @strawberry.field
    def exploit_chain(self, cwe_id: str) -> ExploitChain:
        return exploit_chain.resolve_exploit_chain(cwe_id)

    @strawberry.field
    def cves_for_cwe(self, cwe_id: str, limit: int = 25) -> list[CVE]:
        return exploit_chain.resolve_cves_for_cwe(cwe_id, limit)

    @strawberry.field
    def kev_for_cwe(self, cwe_id: str) -> list[KEVRow]:
        return exploit_chain.resolve_kev_for_cwe(cwe_id)

    # ─── Cohort (per-project investigations) ──────────────────────────────
    @strawberry.field
    def investigations(
        self,
        project_path: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[Investigation]:
        return cohort.resolve_investigations(project_path, status, limit)

    @strawberry.field
    def investigation(
        self, id: int, project_path: str
    ) -> Optional[Investigation]:
        return cohort.resolve_investigation(id, project_path)

    @strawberry.field
    def hypotheses(self, investigation_id: int, project_path: str) -> list[Hypothesis]:
        return cohort.resolve_hypotheses(investigation_id, project_path)

    @strawberry.field
    def evidence(self, hypothesis_id: int, project_path: str) -> list[Evidence]:
        return cohort.resolve_evidence(hypothesis_id, project_path)

    @strawberry.field
    def validations(self, hypothesis_id: int, project_path: str) -> list[Validation]:
        return cohort.resolve_validations(hypothesis_id, project_path)


schema = strawberry.Schema(query=Query)


def execute(query_str: str, variables: dict | None = None) -> dict:
    """Run a GraphQL query in-process and return the result dict."""
    result = schema.execute_sync(query_str, variable_values=variables or {})
    out: dict = {"data": result.data}
    if result.errors:
        out["errors"] = [
            {"message": str(e), "path": getattr(e, "path", None)} for e in result.errors
        ]
    return out
