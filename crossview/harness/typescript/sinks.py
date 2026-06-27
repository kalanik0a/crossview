"""Sink detection in TypeScript/JavaScript/TSX."""
from __future__ import annotations

from pathlib import Path

from crossview.harness.base import Sink
from crossview.harness.typescript.parser import parse


# (ast-grep pattern) → (sink_kind, [CWE IDs], short_callee_label).
# Use $$$ (variadic) for call patterns so additional args don't break the match.
PATTERNS: list[tuple[str, str, list[str], str]] = [
    # XSS / DOM injection
    ("dangerouslySetInnerHTML={{ __html: $X }}", "xss_render", ["CWE-79"], "dangerouslySetInnerHTML"),
    ("$X.innerHTML = $Y",         "xss_render",       ["CWE-79"],  "innerHTML="),
    ("document.write($$$)",       "xss_render",       ["CWE-79"],  "document.write"),

    # Code eval
    ("eval($$$)",                 "code_eval",        ["CWE-95"],  "eval"),
    ("new Function($$$)",         "code_eval",        ["CWE-95"],  "new Function"),

    # Shell exec
    ("child_process.exec($$$)",   "shell_exec",       ["CWE-78"],  "child_process.exec"),
    ("child_process.execSync($$$)", "shell_exec",     ["CWE-78"],  "child_process.execSync"),
    ("child_process.spawn($$$)",  "shell_exec",       ["CWE-78"],  "child_process.spawn"),

    # SSRF / outbound HTTP
    ("fetch($$$)",                "http_fetch",       ["CWE-918"], "fetch"),
    ("axios.get($$$)",            "http_fetch",       ["CWE-918"], "axios.get"),
    ("axios.post($$$)",           "http_fetch",       ["CWE-918"], "axios.post"),
    ("axios.put($$$)",            "http_fetch",       ["CWE-918"], "axios.put"),
    ("axios.delete($$$)",         "http_fetch",       ["CWE-918"], "axios.delete"),

    # Redirect
    ("res.redirect($$$)",         "redirect",         ["CWE-601"], "res.redirect"),
    ("NextResponse.redirect($$$)","redirect",         ["CWE-601"], "NextResponse.redirect"),
    ("redirect($$$)",             "redirect",         ["CWE-601"], "redirect"),

    # SQL
    ("$DB.query($$$)",            "sql_exec",         ["CWE-89"],  ".query"),
    ("$DB.execute($$$)",          "sql_exec",         ["CWE-89"],  ".execute"),

    # LLM (ATLAS-relevant)
    ("$CLIENT.messages.create($$$)",          "llm_call", ["CWE-1426"], "anthropic.messages.create"),
    ("$CLIENT.chat.completions.create($$$)",  "llm_call", ["CWE-1426"], "openai.chat.completions.create"),
    ("$CLIENT.completions.create($$$)",       "llm_call", ["CWE-1426"], "openai.completions.create"),
    ("$CHAIN.invoke($$$)",                    "llm_call", ["CWE-1426"], "langchain.invoke"),

    # Unsafe template / SSTI
    ("Handlebars.compile($$$)",   "template_render",  ["CWE-94"],  "Handlebars.compile"),
]


def _snippet_at(source: str, line: int, span: int = 1) -> str:
    lines = source.split("\n")
    start = max(0, line - 1 - span)
    end = min(len(lines), line + span)
    return "\n".join(lines[start:end])[:200]


def find_sinks(file: Path, source: str, lang: str) -> list[Sink]:
    out: list[Sink] = []
    seen: set[tuple[int, str]] = set()

    try:
        root = parse(source, lang).root()
    except Exception:
        return out

    for pattern, kind, cwes, label in PATTERNS:
        try:
            matches = root.find_all(pattern=pattern)
        except Exception:
            # Some ast-grep patterns may not parse for every grammar; skip.
            continue

        for m in matches:
            line = m.range().start.line + 1
            key = (line, label)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Sink(
                    file=str(file),
                    line=line,
                    kind=kind,
                    risk_cwe=cwes,
                    snippet=_snippet_at(source, line),
                    callee=label,
                )
            )

    return out
