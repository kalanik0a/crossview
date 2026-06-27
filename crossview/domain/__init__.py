"""Domain types — the polyfill layer that every normalizer outputs and every consumer reads."""
from crossview.domain.entities import Entity, Xref, NormalizerResult

__all__ = ["Entity", "Xref", "NormalizerResult"]
