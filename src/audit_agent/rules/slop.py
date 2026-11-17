"""Slop rules: AI-style junk, dead code, and noise that makes a codebase harder to trust."""

from __future__ import annotations

import ast
import json
import re
import sys
from collections.abc import Iterator
from pathlib import PurePosixPath

from audit_agent.models import Category, Finding, Severity
from audit_agent.rules.base import CODE, JS, PY, FileRule, RegexRule, RepoRule, Rule
from audit_agent.workspace import Repo, SourceFile

C = Category.SLOP


# --------------------------------------------------------------------------- regex rules

def _regex_rules() -> list[RegexRule]:
    return [
        RegexRule(
            "SLP001", "Placeholder / stub code", Severity.MEDIUM, C,
            r"(?i)(\bTODO:?\s*implement\b|\bimplement (this|me|later|the (actual|real))\b|your (code|logic|implementation) (goes )?here"
            r"|\bplaceholder (implementation|logic|code|value)\b|\bin a real (implementation|application|app|system|project)\b"
            r"|for (demonstration|demo|illustration) purposes|this is a (simplified|mock|dummy|stub) (version|implementation)"
            r"|replace (this )?with (the )?(actual|real|your)\b|\blorem ipsum\b|\b(mock|fake|dummy) (data|response|implementation) for now"
            r"|\bhardcoded for now\b|\.\.\.\s*rest of (the )?(code|implementation)|\bunimplemented!\(\)|\btodo!\(\))",
            "Placeholder text left in shipped code; the logic it describes probably does not exist.",
            languages=CODE, include_tests=False,
        ),
        RegexRule(
            "SLP002", "AI assistant artifact", Severity.MEDIUM, C,
            r"(?i)(\bas an ai( language model)?\b|\bI (cannot|can't) (assist|help) with\b|\bcertainly!? here\b"
            r"|here('s| is) (the|an?) (updated|revised|complete|modified|corrected) (code|version|implementation)"
            r"|\bI hope this helps\b|\blet me know if you (need|want|have)\b|^\s*```[\w+-]*\s*$)",
            "Text pasted from a chat assistant (or a stray markdown fence) inside source code.",
            languages=CODE,
        ),
        RegexRule(
            "SLP008", "Debugger statement", Severity.MEDIUM, C,
            r"(^\s*debugger\s*;?\s*$|\bpdb\.set_trace\(|\bipdb\.set_trace\(|^\s*breakpoint\(\)|\bbinding\.pry\b|\bvar_dump\(|\bdd\(\$)",
            "Interactive debugger hook left in code; it will hang or leak data in production.",
            languages=CODE, include_tests=False,
        ),
    ]


class DebugPrintRule(FileRule):
    id = "SLP009"
    title = "Debug print"
    severity = Severity.LOW
    category = C
    languages = CODE
    include_tests = False

    _rx = re.compile(r"(^\s*print\(|\bconsole\.(log|debug)\(|System\.(out|err)\.println\(|\bprintln!\(|\bputs\s|\bvar_export\()")
    _entrypoint = re.compile(r"(^|/)(cli|main|__main__|manage|setup)\.\w+$|(^|/)(bin|scripts?|examples?|tools)/")

    def applies_to(self, file: SourceFile) -> bool:
        # Printing is the job of CLIs and scripts; only flag it in library code.
        if self._entrypoint.search(file.path) or "__name__ == \"__main__\"" in file.text or "__name__ == '__main__'" in file.text:
            return False
        return super().applies_to(file)

    def check(self, file: SourceFile) -> Iterator[Finding]:
        for lineno, line in enumerate(file.lines, start=1):
            if self._rx.search(line):
                yield self.finding(file.path, lineno, "Print-style debugging in library code. Use a logger or remove it.", line)


# --------------------------------------------------------------------------- comments

_COMMENT = re.compile(r"^\s*(#|//)\s?(.*)$")
_WORD = re.compile(r"[A-Za-z]+|\d+")
_STOP = {"the", "a", "an", "to", "of", "by", "and", "this", "is", "we", "it", "for", "with", "from", "in", "on",
         "value", "variable", "new", "into", "then", "our", "its", "be", "now", "here", "one"}
_RESTATE_VERBS = {"set", "sets", "increment", "increments", "return", "returns", "call", "calls", "import", "imports",
                  "define", "defines", "create", "creates", "initialize", "initialise", "add", "adds", "loop", "iterate",
                  "check", "checks", "print", "prints", "assign", "get", "gets", "update", "updates", "append", "declare"}


def _words(text: str) -> list[str]:
    """Split identifiers too: getUserName / get_user_name -> get, user, name."""
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ")
    return [w.lower() for w in _WORD.findall(spaced)]


class RestatingCommentRule(FileRule):
    """`# increment counter by 1` above `counter += 1`: the comment adds nothing."""

    id = "SLP003"
    title = "Comment restates the code"
    severity = Severity.LOW
    category = C
    languages = CODE

    def check(self, file: SourceFile) -> Iterator[Finding]:
        lines = file.lines
        for i, line in enumerate(lines[:-1]):
            m = _COMMENT.match(line)
            nxt = lines[i + 1]
            if not m or not nxt.strip() or _COMMENT.match(nxt):
                continue
            words = _words(m.group(2))
            if not words or len(words) > 7 or words[0] not in _RESTATE_VERBS:
                continue
            content = {w for w in words[1:] if w not in _STOP}
            code = set(_words(nxt)) | {w.rstrip("s") for w in _words(nxt)}
            if content and all(w in code or w.rstrip("s") in code for w in content):
                yield self.finding(file.path, i + 1, "Comment only repeats what the next line says; explain *why* or delete it.", line)


_CODE_LIKE = re.compile(
    r"^(def |class |import |from [\w.]+ import |return\b|(if|elif|for|while|with|try|except)\b.*:$|else:$"
    r"|print\(|(const|let|var|function|public|private|func) |[\w.\[\]]+\s*(=|\+=|-=)\s*\S|[\w.]+\(.*\)\s*;?$|[{}]\s*$|.*;\s*$)"
)


class CommentedOutCodeRule(FileRule):
    id = "SLP007"
    title = "Commented-out code block"
    severity = Severity.LOW
    category = C
    languages = CODE
    min_block = 3

    def check(self, file: SourceFile) -> Iterator[Finding]:
        block: list[tuple[int, str]] = []
        for lineno, line in enumerate([*file.lines, ""], start=1):  # sentinel flushes the last block
            m = _COMMENT.match(line)
            if m and not line.lstrip().startswith(("#!", "# type:", "# noqa", "# -*-")):
                block.append((lineno, m.group(2).strip()))
                continue
            code_lines = sum(1 for _, text in block if _CODE_LIKE.match(text))
            if len(block) >= self.min_block and code_lines >= max(self.min_block, len(block) * 0.6):
                start = block[0][0]
                yield self.finding(file.path, start, f"{len(block)} lines of commented-out code. Version control remembers it; delete it.",
                                   block[0][1])
            block = []


# --------------------------------------------------------------------------- duplication

class DuplicateBlockRule(RepoRule):
    """Copy-paste detection: identical runs of `window` normalised lines across the repo."""

    id = "SLP004"
    title = "Duplicated code block"
    severity = Severity.LOW
    category = C
    window = 6
    min_chars = 120  # ignore windows of braces and one-word lines

    def check(self, repo: Repo) -> Iterator[Finding]:
        seen: dict[str, tuple[str, int]] = {}  # window text -> first occurrence
        for file in repo.files:
            if file.suffix not in CODE or file.is_test:
                continue
            norm = [(n, ln.strip()) for n, ln in enumerate(file.lines, start=1)
                    if ln.strip() and not _COMMENT.match(ln)]
            last_dup_end = -1
            for i in range(len(norm) - self.window + 1):
                chunk = norm[i:i + self.window]
                text = "\n".join(t for _, t in chunk)
                if sum(c.isalnum() for c in text) < self.min_chars:
                    continue
                key = text
                start, end = chunk[0][0], chunk[-1][0]
                if key not in seen:
                    seen[key] = (file.path, start)
                    continue
                if start > last_dup_end:  # report each duplicated region once
                    other_path, other_line = seen[key]
                    if (other_path, other_line) != (file.path, start):
                        yield self.finding(file.path, start, f"Block duplicates {other_path}:{other_line}. Extract a shared function.",
                                           chunk[0][1])
                last_dup_end = end


# --------------------------------------------------------------------------- Python AST

_IMPORT_ALIASES = {  # import name -> distribution name, for the most common mismatches
    "yaml": "pyyaml", "cv2": "opencv-python", "pil": "pillow", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv", "jwt": "pyjwt", "dateutil": "python-dateutil", "magic": "python-magic",
    "google": "google-api-python-client", "attr": "attrs", "crypto": "pycryptodome", "serial": "pyserial",
    "docx": "python-docx", "git": "gitpython", "zmq": "pyzmq", "multipart": "python-multipart",
    "pkg_resources": "setuptools", "setuptools": "setuptools", "_pytest": "pytest",
}


def _norm_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_python_deps(repo: Repo) -> set[str]:
    """Best-effort union of dependencies from every Python manifest in the repo."""
    deps: set[str] = set()
    name_rx = re.compile(r"^\s*[\"']?([A-Za-z0-9][A-Za-z0-9._-]*)")
    for f in repo.files:
        if re.search(r"requirements[\w.-]*\.(txt|in)$", f.name) or f.name in {"constraints.txt"}:
            for line in f.lines:
                if (m := name_rx.match(line.split("#")[0])) and not line.strip().startswith("-"):
                    deps.add(_norm_dist(m.group(1)))
        elif f.name in {"pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "environment.yml"}:
            # Quoted requirement strings such as "requests>=2" or 'numpy', plus poetry/pipenv "name = ..." keys.
            for m in re.finditer(r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;\"']|$)", f.text, re.M):
                deps.add(_norm_dist(m.group(1)))
            for m in re.finditer(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", f.text, re.M):
                deps.add(_norm_dist(m.group(1)))
            for m in re.finditer(r"^\s*-\s*([A-Za-z0-9][A-Za-z0-9._-]*)", f.text, re.M):
                deps.add(_norm_dist(m.group(1)))
    return deps


def local_python_modules(repo: Repo) -> set[str]:
    """Every name that could be a first-party import: module stems and package dirs."""
    names: set[str] = set()
    for f in repo.files:
        if f.is_python:
            p = PurePosixPath(f.path)
            names.add(p.stem)
            names.update(p.parts[:-1])
    return names


class UnknownImportRule(RepoRule):
    """Imports that are not stdlib, not first-party and not declared: hallucinated or undeclared."""

    id = "SLP005"
    title = "Unknown import (hallucinated or undeclared)"
    severity = Severity.MEDIUM
    category = C

    def check(self, repo: Repo) -> Iterator[Finding]:
        yield from self._python(repo)
        yield from self._javascript(repo)

    def _python(self, repo: Repo) -> Iterator[Finding]:
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        local = local_python_modules(repo)
        deps = declared_python_deps(repo)
        for f in repo.files:
            tree = f.python_ast
            if tree is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    mods = [node.module]
                else:
                    continue
                for mod in mods:
                    top = mod.split(".")[0]
                    if top in stdlib or top in local:
                        continue
                    candidates = {_norm_dist(top), _norm_dist(_IMPORT_ALIASES.get(top.lower(), top))}
                    if candidates & deps:
                        continue
                    yield self.finding(f.path, node.lineno,
                                       f"'{mod}' is not stdlib, not a local module, and not declared in any dependency manifest. "
                                       "It may be hallucinated, misspelled, or missing from requirements.",
                                       f.lines[node.lineno - 1] if node.lineno <= len(f.lines) else "")

    _NODE_BUILTINS = {
        "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs", "http", "http2", "https",
        "net", "os", "path", "perf_hooks", "process", "querystring", "readline", "stream", "string_decoder", "timers",
        "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib", "module", "async_hooks", "inspector",
    }
    _JS_IMPORT = re.compile(r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\s*\(\s*|^\s*import\s+)["']([^"']+)["']""")

    def _javascript(self, repo: Repo) -> Iterator[Finding]:
        manifests = [f for f in repo.files if f.name == "package.json"]
        if not manifests:
            return  # no manifest: nothing to compare against
        deps: set[str] = set()
        for m in manifests:
            try:
                data = json.loads(m.text)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps.update((data.get(section) or {}).keys())
            if isinstance(data.get("name"), str):
                deps.add(data["name"])
        for f in repo.files:
            if f.suffix not in JS:
                continue
            for lineno, line in enumerate(f.lines, start=1):
                for spec in self._JS_IMPORT.findall(line):
                    if spec.startswith((".", "/", "node:", "@/", "~/", "#", "http")):
                        continue
                    parts = spec.split("/")
                    pkg = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
                    if pkg in self._NODE_BUILTINS or pkg in deps:
                        continue
                    yield self.finding(f.path, lineno, f"'{pkg}' is imported but not listed in package.json. "
                                       "It may be hallucinated or missing from dependencies.", line)


class UnusedImportRule(FileRule):
    id = "SLP006"
    title = "Unused import"
    severity = Severity.LOW
    category = C
    languages = PY

    def applies_to(self, file: SourceFile) -> bool:
        return super().applies_to(file) and file.name != "__init__.py"  # re-exports live there

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        imported: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported[a.asname or a.name.split(".")[0]] = node.lineno
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                for a in node.names:
                    if a.name != "*":
                        imported[a.asname or a.name] = node.lineno
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        # Names referenced from string annotations or __all__ count as used.
        strings = " ".join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str))
        used |= set(re.findall(r"[A-Za-z_]\w*", strings))
        for name, lineno in sorted(imported.items(), key=lambda kv: kv[1]):
            line = file.lines[lineno - 1] if lineno <= len(file.lines) else ""
            if name not in used and "noqa" not in line:
                yield self.finding(file.path, lineno, f"'{name}' is imported but never used.", line)


class UnreachableCodeRule(FileRule):
    id = "SLP010"
    title = "Unreachable code"
    severity = Severity.MEDIUM
    category = C
    languages = PY

    _TERMINAL = (ast.Return, ast.Raise, ast.Continue, ast.Break)

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        for node in ast.walk(tree):
            for field in ("body", "orelse", "finalbody"):
                stmts = getattr(node, field, None)
                if not isinstance(stmts, list):
                    continue
                for prev, stmt in zip(stmts, stmts[1:]):
                    if isinstance(prev, self._TERMINAL) and isinstance(stmt, ast.stmt):
                        kind = type(prev).__name__.lower()
                        yield self.finding(file.path, stmt.lineno, f"Statement after `{kind}` can never run (dead code).",
                                           file.lines[stmt.lineno - 1])
                        break


def rules() -> list[Rule]:
    return [*_regex_rules(), DebugPrintRule(), RestatingCommentRule(), CommentedOutCodeRule(), DuplicateBlockRule(),
            UnknownImportRule(), UnusedImportRule(), UnreachableCodeRule()]
