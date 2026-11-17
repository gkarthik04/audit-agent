# audit: ignore-file -- these tests deliberately contain the patterns the rules detect.
import pytest

from audit_agent.rules import slop
from audit_agent.rules.slop import (
    CommentedOutCodeRule,
    DebugPrintRule,
    DuplicateBlockRule,
    RestatingCommentRule,
    UnknownImportRule,
    UnreachableCodeRule,
    UnusedImportRule,
)
from conftest import run_file_rule, run_repo_rule


def regex_rule(rule_id: str):
    return next(r for r in slop.rules() if r.id == rule_id)


@pytest.mark.parametrize("line", [
    "# TODO: implement",
    "// your code here",
    "# In a real application you would hash this",
    "# This is a simplified version of the algorithm",
    "return 42  # placeholder value",
])
def test_placeholder_code(line):
    assert run_file_rule(regex_rule("SLP001"), "a.py", line) != []


def test_placeholders_in_tests_are_allowed():
    assert run_file_rule(regex_rule("SLP001"), "tests/test_a.py", "# your code here") == []


@pytest.mark.parametrize("line", ["# Certainly! Here is the code", "// As an AI language model, I", "```python"])
def test_ai_artifacts(line):
    assert run_file_rule(regex_rule("SLP002"), "a.py", line) != []


class TestUnknownImports:
    def test_flags_undeclared_and_accepts_declared_stdlib_local_and_aliases(self):
        files = {
            "requirements.txt": "requests>=2\nPyYAML==6.0\n",
            "pkg/helpers.py": "",
            "pkg/main.py": """
                import os
                import requests
                import yaml
                from pkg import helpers
                import helpers
                import fastjsonx
                from . import sibling
            """,
        }
        hits = run_repo_rule(UnknownImportRule(), files)
        assert [(h.path, h.line) for h in hits] == [("pkg/main.py", 6)]
        assert "fastjsonx" in hits[0].message

    def test_pyproject_dependencies_count_as_declared(self):
        files = {
            "pyproject.toml": '[project]\ndependencies = ["httpx>=0.27", "rich"]\n',
            "app.py": "import httpx\nimport rich.console\n",
        }
        assert run_repo_rule(UnknownImportRule(), files) == []

    def test_js_import_missing_from_package_json(self):
        files = {
            "package.json": '{"dependencies": {"express": "4.19.2", "@scope/ui": "1.0.0"}}',
            "a.js": """
                const express = require('express');
                import ui from '@scope/ui/button';
                import fs from 'fs';
                import x from './local';
                import ghost from 'left-padder-pro';
            """,
        }
        hits = run_repo_rule(UnknownImportRule(), files)
        assert [h.line for h in hits] == [5]


def test_unused_imports():
    code = """
    import os
    import sys as system
    from typing import Optional, List
    import json  # noqa
    x: "Optional[int]" = None
    print(system.argv)
    """
    hits = run_file_rule(UnusedImportRule(), "a.py", code)
    assert sorted(h.message.split("'")[1] for h in hits) == ["List", "os"]


def test_unused_imports_skips_init_reexports():
    assert run_file_rule(UnusedImportRule(), "pkg/__init__.py", "from .a import b\n") == []


def test_unreachable_code():
    code = """
    def f(x):
        if x:
            return 1
            print("never")
        for i in x:
            continue
        return 2
    """
    hits = run_file_rule(UnreachableCodeRule(), "a.py", code)
    assert [h.line for h in hits] == [4]


def test_restating_comments():
    code = """
    # increment counter by 1
    counter += 1
    # retry because the API is eventually consistent
    counter += 1
    // return the result
    return result;
    """
    hits = run_file_rule(RestatingCommentRule(), "a.py", code)
    assert [h.line for h in hits] == [1, 5]


def test_commented_out_code_block():
    code = """
    # old_value = load(path)
    # if old_value:
    #     cache[path] = old_value
    x = 1
    # This explains the algorithm in prose,
    # across several lines of normal English
    # without looking like code at all
    y = 2
    """
    hits = run_file_rule(CommentedOutCodeRule(), "a.py", code)
    assert [h.line for h in hits] == [1]


def test_duplicate_blocks_reported_once_per_region():
    block = "\n".join(f"value_{i} = compute_something(argument_{i}, other_{i})" for i in range(8))
    files = {"a.py": block + "\n", "b.py": "x = 1\n" + block + "\n", "c.py": "unrelated = True\n"}
    hits = run_repo_rule(DuplicateBlockRule(), files)
    assert [(h.path, h.line) for h in hits] == [("b.py", 2)]
    assert "a.py:1" in hits[0].message


def test_debug_print_only_in_library_code():
    rule = DebugPrintRule()
    assert run_file_rule(rule, "lib/core.py", "print('x')\n") != []
    assert run_file_rule(rule, "lib/cli.py", "print('x')\n") == []
    assert run_file_rule(rule, "scripts/seed.py", "print('x')\n") == []
    assert run_file_rule(rule, "tests/test_core.py", "print('x')\n") == []
    assert run_file_rule(rule, "tool.py", "print('x')\nif __name__ == \"__main__\":\n    pass\n") == []
