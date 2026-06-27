"""Identify dangerous operations in Python code.

Each pattern maps to a (sink_kind, candidate_cwes) pair so that downstream
stages can join findings to the canonical entities in crossview.db.
"""
import ast
from pathlib import Path

from crossview.harness.base import Sink
from crossview.harness.python.ast_walker import call_name, line_snippet

# Exact dotted-name match: callee → (kind, [CWE IDs])
EXACT_PATTERNS: dict[str, tuple[str, list[str]]] = {
    # Shell / subprocess
    "subprocess.run": ("shell_exec", ["CWE-78", "CWE-88"]),
    "subprocess.Popen": ("shell_exec", ["CWE-78", "CWE-88"]),
    "subprocess.call": ("shell_exec", ["CWE-78", "CWE-88"]),
    "subprocess.check_output": ("shell_exec", ["CWE-78", "CWE-88"]),
    "subprocess.check_call": ("shell_exec", ["CWE-78", "CWE-88"]),
    "subprocess.getoutput": ("shell_exec", ["CWE-78"]),
    "os.system": ("shell_exec", ["CWE-78"]),
    "os.popen": ("shell_exec", ["CWE-78"]),
    "os.exec": ("shell_exec", ["CWE-78"]),
    "os.execv": ("shell_exec", ["CWE-78"]),
    "os.execve": ("shell_exec", ["CWE-78"]),
    "os.spawnl": ("shell_exec", ["CWE-78"]),

    # Code eval
    "eval": ("code_eval", ["CWE-95", "CWE-94"]),
    "exec": ("code_eval", ["CWE-95", "CWE-94"]),
    "compile": ("code_eval", ["CWE-95"]),

    # Unsafe deserialization
    "pickle.loads": ("unsafe_deserialize", ["CWE-502"]),
    "pickle.load": ("unsafe_deserialize", ["CWE-502"]),
    "cPickle.loads": ("unsafe_deserialize", ["CWE-502"]),
    "cPickle.load": ("unsafe_deserialize", ["CWE-502"]),
    "yaml.load": ("unsafe_deserialize", ["CWE-502"]),  # FP-prone: SafeLoader is fine
    "yaml.unsafe_load": ("unsafe_deserialize", ["CWE-502"]),
    "marshal.loads": ("unsafe_deserialize", ["CWE-502"]),
    "marshal.load": ("unsafe_deserialize", ["CWE-502"]),
    "shelve.open": ("unsafe_deserialize", ["CWE-502"]),

    # SSRF / outbound HTTP
    "requests.get": ("http_fetch", ["CWE-918"]),
    "requests.post": ("http_fetch", ["CWE-918"]),
    "requests.put": ("http_fetch", ["CWE-918"]),
    "requests.delete": ("http_fetch", ["CWE-918"]),
    "requests.request": ("http_fetch", ["CWE-918"]),
    "httpx.get": ("http_fetch", ["CWE-918"]),
    "httpx.post": ("http_fetch", ["CWE-918"]),
    "httpx.AsyncClient.get": ("http_fetch", ["CWE-918"]),
    "httpx.AsyncClient.post": ("http_fetch", ["CWE-918"]),
    "urllib.request.urlopen": ("http_fetch", ["CWE-918"]),

    # Templating / response (XSS / SSTI)
    "flask.render_template_string": ("template_render", ["CWE-94", "CWE-79"]),
    "jinja2.Template": ("template_render", ["CWE-94"]),
    "jinja2.Environment.from_string": ("template_render", ["CWE-94"]),

    # Redirects
    "flask.redirect": ("redirect", ["CWE-601"]),
    "fastapi.responses.RedirectResponse": ("redirect", ["CWE-601"]),

    # XML
    "xml.etree.ElementTree.parse": ("xxe", ["CWE-611"]),
    "xml.etree.ElementTree.fromstring": ("xxe", ["CWE-611"]),
    "xml.dom.minidom.parseString": ("xxe", ["CWE-611"]),
    "xml.sax.parse": ("xxe", ["CWE-611"]),

    # LLM (ATLAS-relevant — user input flowing here is AML.T0051)
    "anthropic.Anthropic.messages.create": ("llm_call", ["CWE-1426"]),
    "anthropic.AsyncAnthropic.messages.create": ("llm_call", ["CWE-1426"]),
    "openai.ChatCompletion.create": ("llm_call", ["CWE-1426"]),
    "openai.OpenAI.chat.completions.create": ("llm_call", ["CWE-1426"]),
    "openai.AsyncOpenAI.chat.completions.create": ("llm_call", ["CWE-1426"]),

    # File I/O — only risky with user-controlled paths
    "open": ("file_io", ["CWE-22", "CWE-73"]),
}

# Suffix-tuple patterns for cases where the receiver is a variable name.
# Examples covered:
#   db.execute(...) / cursor.execute(...) / session.execute(...)
#   client.messages.create(...)             ← Anthropic
#   client.chat.completions.create(...)     ← OpenAI
#   self.client.messages.create(...)        ← typical class-attr usage
#
# Each entry is (suffix_segments, (sink_kind, [cwe_ids])). Match wins if the
# tail of the dotted call name equals the suffix.
SUFFIX_PATTERNS: list[tuple[tuple[str, ...], tuple[str, list[str]]]] = [
    # SQL
    (("execute",),       ("sql_exec", ["CWE-89"])),
    (("executemany",),   ("sql_exec", ["CWE-89"])),
    (("executescript",), ("sql_exec", ["CWE-89"])),

    # LLM (ATLAS-relevant)
    (("messages", "create"),                ("llm_call", ["CWE-1426"])),  # Anthropic
    (("chat", "completions", "create"),     ("llm_call", ["CWE-1426"])),  # OpenAI new
    (("completions", "create"),             ("llm_call", ["CWE-1426"])),  # OpenAI legacy
    (("invoke",),                           ("llm_call", ["CWE-1426"])),  # langchain
    (("ainvoke",),                          ("llm_call", ["CWE-1426"])),  # langchain async
    (("astream",),                          ("llm_call", ["CWE-1426"])),  # langchain stream
]


def find_sinks(file: Path, tree: ast.Module, source_lines: list[str]) -> list[Sink]:
    sinks: list[Sink] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = call_name(node)
        if not name:
            continue

        match = EXACT_PATTERNS.get(name)

        # Suffix match (only if no exact)
        if not match:
            segments = name.split(".")
            for suffix, info in SUFFIX_PATTERNS:
                if len(segments) >= len(suffix) and tuple(segments[-len(suffix):]) == suffix:
                    match = info
                    break

        if not match:
            continue

        kind, cwes = match
        sinks.append(
            Sink(
                file=str(file),
                line=node.lineno,
                kind=kind,
                risk_cwe=cwes,
                snippet=line_snippet(source_lines, node.lineno),
                callee=name,
            )
        )

    return sinks
