# audit: ignore-file -- these tests deliberately contain the patterns the rules detect.
from audit_agent.models import Severity
from audit_agent.rules import gaps
from audit_agent.rules.gaps import (
    MissingProjectFilesRule,
    MissingTestsRule,
    MissingTimeoutRule,
    PythonErrorHandlingRule,
    TodoMarkerRule,
    UnfinishedFunctionRule,
)
from conftest import run_file_rule, run_repo_rule


def regex_rule(rule_id: str):
    return next(r for r in gaps.rules() if r.id == rule_id and hasattr(r, "pattern"))


def test_todo_markers_only_in_comments():
    code = """
    # TODO: cache this
    x = 1  // FIXME broken on windows
    TODO_LIST = []
    msg = "TODO"
    # TODO: implement me
    """
    hits = run_file_rule(TodoMarkerRule(), "a.py", code)
    assert [(h.line, h.severity) for h in hits] == [(1, Severity.INFO), (2, Severity.LOW)]


def test_swallowed_and_bare_except():
    code = """
    try:
        a()
    except ValueError:
        pass
    try:
        b()
    except:
        log()
    try:
        c()
    except KeyError:
        handle()
    """
    hits = run_file_rule(PythonErrorHandlingRule(), "a.py", code)
    assert [(h.rule_id, h.line) for h in hits] == [("GAP002", 3), ("GAP003", 7)]


def test_empty_catch_in_other_languages():
    rule = regex_rule("GAP002")
    assert run_file_rule(rule, "a.js", "try { x() } catch (e) {}") != []
    assert run_file_rule(rule, "a.go", "if err != nil {}") != []
    assert run_file_rule(rule, "a.js", "try { x() } catch (e) { log(e) }") == []


def test_unfinished_functions():
    code = '''
    import abc
    from typing import Protocol

    def stub():
        pass

    def documented_only():
        """Does things."""

    def later():
        raise NotImplementedError("soon")

    def real():
        return 1

    class Base(abc.ABC):
        @abc.abstractmethod
        def run(self): ...

    class Greeter(Protocol):
        def greet(self) -> str: ...
    '''
    hits = run_file_rule(UnfinishedFunctionRule(), "a.py", code)
    assert [(h.line, h.severity) for h in hits] == [(4, Severity.MEDIUM), (7, Severity.MEDIUM), (10, Severity.LOW)]


def test_missing_timeout():
    code = "requests.get(url)\nrequests.post(url, timeout=5)\n"
    assert [h.line for h in run_file_rule(MissingTimeoutRule(), "a.py", code)] == [1]


def test_go_discarded_error():
    rule = regex_rule("GAP007")
    assert run_file_rule(rule, "a.go", "n, _ := strconv.Atoi(s)") != []
    assert run_file_rule(rule, "a.go", "for _, v := range items {") == []


class TestMissingTests:
    BODY = "\n".join(f"line_{i} = {i}" for i in range(20))

    def test_no_tests_at_all(self):
        hits = run_repo_rule(MissingTestsRule(), {"app/billing.py": self.BODY})
        assert len(hits) == 1 and hits[0].path == "." and hits[0].severity is Severity.MEDIUM

    def test_untested_module_is_reported(self):
        files = {"app/billing.py": self.BODY, "app/users.py": self.BODY,
                 "tests/test_billing.py": "from app import billing\n", "app/tiny.py": "x = 1\n"}
        hits = run_repo_rule(MissingTestsRule(), files)
        assert [h.path for h in hits] == ["app/users.py"]


def test_missing_project_files():
    hits = run_repo_rule(MissingProjectFilesRule(), {"main.py": "", "readme.md": ""})
    messages = " ".join(h.message for h in hits)
    assert len(hits) == 2 and ".gitignore" in messages and "LICENSE" in messages
