"""audit_agent: a small, pluggable, language-agnostic code-audit agent."""

from audit_agent.engine import scan
from audit_agent.models import Category, Finding, ScanResult, Severity

__all__ = ["scan", "Category", "Finding", "ScanResult", "Severity"]
__version__ = "0.1.0"
