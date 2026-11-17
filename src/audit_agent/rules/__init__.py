"""Rule registry.

Built-in rules come from the three category modules. Third-party packages can add
rules without touching this code by exposing a zero-argument callable that returns
a list of `Rule` objects under the `audit_agent.rules` entry-point group:

    [project.entry-points."audit_agent.rules"]
    my_rules = "my_pkg.rules:rules"
"""

from __future__ import annotations

import warnings
from importlib.metadata import entry_points

from audit_agent.rules import gaps, security, slop
from audit_agent.rules.base import FileRule, RegexRule, RepoRule, Rule

__all__ = ["Rule", "FileRule", "RegexRule", "RepoRule", "builtin_rules", "load_rules"]


def builtin_rules() -> list[Rule]:
    return [*security.rules(), *slop.rules(), *gaps.rules()]


def plugin_rules() -> list[Rule]:
    found: list[Rule] = []
    for ep in entry_points(group="audit_agent.rules"):
        try:
            found.extend(ep.load()())
        except Exception as exc:  # a broken plugin must not break the scan
            warnings.warn(f"failed to load rule plugin {ep.name!r}: {exc}", stacklevel=2)
    return found


def load_rules(enable: set[str] | None = None, disable: set[str] | None = None) -> list[Rule]:
    """All rules, optionally filtered by rule-id prefix (e.g. {"SEC"} or {"SLP003"})."""
    rules = builtin_rules() + plugin_rules()
    if enable:
        rules = [r for r in rules if any(r.id.startswith(p) for p in enable)]
    if disable:
        rules = [r for r in rules if not any(r.id.startswith(p) for p in disable)]
    return rules
