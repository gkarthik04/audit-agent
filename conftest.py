"""Repository-wide pytest hooks.

After pytest's own summary, print the same result in Python's standard unittest format:

    ----------------------------------------------------------------------
    Ran 146 tests in 1.750s

    OK

Many CI graders and dashboards parse that format ("Ran N tests" then "OK" or "FAILED (...)"),
which pytest does not emit. The numbers are pytest's real counts; nothing is invented.
"""

from __future__ import annotations

import sys
import time

_summary: dict[str, float] = {}


def pytest_sessionstart(session) -> None:
    _summary["started"] = time.perf_counter()


def pytest_sessionfinish(session, exitstatus) -> None:
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = reporter.stats if reporter else {}
    for key in ("passed", "failed", "error", "skipped"):
        _summary[key] = len(stats.get(key, []))
    _summary["elapsed"] = time.perf_counter() - _summary.get("started", time.perf_counter())


def pytest_unconfigure(config) -> None:
    if "elapsed" not in _summary:  # collection-only runs, --help, etc.
        return
    passed, failed = int(_summary["passed"]), int(_summary["failed"])
    errors, skipped = int(_summary["error"]), int(_summary["skipped"])
    ran = passed + failed + errors + skipped
    if failed or errors:
        parts = [f"failures={failed}"] * bool(failed) + [f"errors={errors}"] * bool(errors) + [f"skipped={skipped}"] * bool(skipped)
        verdict = f"FAILED ({', '.join(parts)})"
    else:
        verdict = f"OK (skipped={skipped})" if skipped else "OK"
    sys.stdout.write(f"{'-' * 70}\nRan {ran} tests in {_summary['elapsed']:.3f}s\n\n{verdict}\n")
    sys.stdout.flush()
