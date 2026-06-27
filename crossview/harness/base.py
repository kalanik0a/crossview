"""Harness types — what every language harness produces.

The harness is the agent's structural lens on a codebase: it enumerates
where untrusted input enters (Entrypoints), where dangerous operations
happen (Sinks), and where it can prove the two are connected (DataEdges).
Stage 1 (Survey) and Stage 2 (Prematch) consume these.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class Entrypoint:
    """One way external input enters the system."""

    file: str
    line: int
    kind: str            # http_route | cli_command | event_handler | webhook | scheduled
    framework: str       # fastapi | flask | django | typer | click | next | express | hono | apscheduler | ...
    method: str | None = None    # GET, POST, ANY (for http_route)
    path: str | None = None      # /api/foo/{id}
    handler_name: str | None = None
    parameters: list[dict] = field(default_factory=list)


@dataclass
class Sink:
    """One operation that becomes dangerous when reached by user input."""

    file: str
    line: int
    kind: str            # sql_exec | shell_exec | code_eval | unsafe_deserialize | http_fetch | file_io | template_render | redirect | llm_call
    risk_cwe: list[str]  # candidate CWE IDs this sink could exhibit
    snippet: str         # 1-3 lines of surrounding code
    callee: str          # dotted name of the function being called


@dataclass
class DataEdge:
    """A connection from a source (param/input) to a sink, when traceable."""

    source_file: str
    source_line: int
    source_param: str
    sink_file: str
    sink_line: int
    sink_kind: str


@dataclass
class FileMap:
    """Per-file analysis result."""

    file: str
    language: str
    entrypoints: list[Entrypoint] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    edges: list[DataEdge] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    frameworks_detected: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


class CodeHarness(Protocol):
    """One per language."""

    languages: tuple[str, ...]
    extensions: set[str]

    def can_handle(self, file: Path) -> bool: ...
    def survey(self, file: Path) -> FileMap: ...
