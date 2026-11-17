"""The scan pipeline: load repo -> run rules -> suppress -> dedupe -> sort.

Deterministic and offline. The optional LLM pass (llm.py) runs *after* this and
only ever removes or annotates findings; it never invents new ones.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Iterable
from pathlib import Path

from audit_agent.models import Finding, ScanResult, Severity
from audit_agent.rules import FileRule, RepoRule, Rule, load_rules
from audit_agent.workspace import Repo, load_repo

# `# audit: ignore` silences every rule on that line; `# audit: ignore[SEC002,SLP]` only those ids/prefixes.
# `# audit: ignore-file[...]` within the first 5 lines does the same for the whole file.
_SUPPRESS = re.compile(r"audit:\s*ignore(?:\[([\w,\s]+)\])?", re.IGNORECASE)
_SUPPRESS_FILE = re.compile(r"audit:\s*ignore-file(?:\[([\w,\s]+)\])?", re.IGNORECASE)


def scan(
    path: str | Path,
    rules: list[Rule] | None = None,
    exclude: list[str] | None = None,
    disable: set[str] | None = None,
    min_severity: Severity = Severity.INFO,
) -> ScanResult:
    repo = load_repo(path, exclude=exclude)
    active = rules if rules is not None else load_rules(disable=disable)
    findings = run_rules(repo, active)
    if disable:  # a rule may emit sibling ids (e.g. the Python AST rule emits SEC003 and SEC004)
        findings = [f for f in findings if not any(f.rule_id.startswith(p) for p in disable)]
    findings = [f for f in findings if f.severity.rank >= min_severity.rank and not _suppressed(repo, f)]
    # Keep the root as the user typed it: reports stay portable and do not leak home-directory paths.
    return ScanResult(root=Path(path).as_posix(), files_scanned=len(repo.files), findings=sort_findings(dedupe(findings)),
                      rules_run=len(active))


def run_rules(repo: Repo, rules: Iterable[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        try:
            if isinstance(rule, RepoRule):
                findings.extend(rule.check(repo))
            elif isinstance(rule, FileRule):
                for file in repo.files:
                    if rule.applies_to(file):
                        findings.extend(rule.check(file))
        except Exception as exc:  # one buggy rule must never sink the whole scan
            warnings.warn(f"rule {rule.id} crashed: {exc!r}", stacklevel=2)
    return findings


def _suppressed(repo: Repo, f: Finding) -> bool:
    file = repo.get(f.path)
    if file is None:
        return False
    header = "\n".join(file.lines[:5])
    if (m := _SUPPRESS_FILE.search(header)) and _ids_match(f.rule_id, m.group(1)):
        return True
    if not f.line or f.line > len(file.lines):
        return False
    m = _SUPPRESS.search(file.lines[f.line - 1])
    return bool(m) and _ids_match(f.rule_id, m.group(1))


def _ids_match(rule_id: str, ids: str | None) -> bool:
    """No list means "all rules"; otherwise ids are prefixes, so [SEC] covers SEC001..SEC010."""
    return ids is None or any(rule_id.startswith(i.strip()) for i in ids.split(",") if i.strip())


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.category.value, f.path, f.line, f.rule_id))
