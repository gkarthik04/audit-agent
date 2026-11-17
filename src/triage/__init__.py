"""Support-ticket triage API: GET /health, POST /classify."""

from triage.classifier import CATEGORIES, URGENCIES, classify

__all__ = ["CATEGORIES", "URGENCIES", "classify"]
