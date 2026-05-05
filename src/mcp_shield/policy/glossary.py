"""Business-term glossary lookup."""

from __future__ import annotations

from .loader import Policy


def lookup(term: str, policy: Policy) -> str | None:
    for entry in policy.glossary:
        if entry.term == term:
            return entry.sql
    return None


def list_terms(policy: Policy) -> list[str]:
    return [entry.term for entry in policy.glossary]
