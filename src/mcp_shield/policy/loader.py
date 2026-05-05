"""Policy file schema and loader (YAML → Policy)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class TableColumns(BaseModel):
    table: str
    deny_columns: list[str] = Field(default_factory=list)


class RBACRule(BaseModel):
    role: str
    allow_tools: list[str] = Field(default_factory=list)
    allow_tables: list[str] = Field(default_factory=list)
    deny_tables: list[str] = Field(default_factory=list)


class RLSRule(BaseModel):
    role: str
    table: str
    predicate: str


class RedactionRule(BaseModel):
    table: str
    column: str
    mask: str


class GlossaryEntry(BaseModel):
    term: str
    sql: str


class Policy(BaseModel):
    rbac: list[RBACRule] = Field(default_factory=list)
    rls: list[RLSRule] = Field(default_factory=list)
    redaction: list[RedactionRule] = Field(default_factory=list)
    glossary: list[GlossaryEntry] = Field(default_factory=list)
    deny_tables: list[str] = Field(default_factory=list)
    deny_columns: list[TableColumns] = Field(default_factory=list)


def load_policy(path: Path) -> Policy:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return Policy.model_validate(data)


def merge_policies(*policies: Policy) -> Policy:
    """Combine policies with permissive semantics: rule lists concatenate,
    glossary terms are later-wins, deny-lists union.

    Designed for startup-time composition (base + environment + tenant overrides).
    """
    if not policies:
        return Policy()

    rbac: list[RBACRule] = []
    rls: list[RLSRule] = []
    redaction: list[RedactionRule] = []
    glossary_by_term: dict[str, GlossaryEntry] = {}
    deny_tables: list[str] = []
    deny_columns_by_table: dict[str, list[str]] = {}

    for p in policies:
        rbac.extend(p.rbac)
        rls.extend(p.rls)
        redaction.extend(p.redaction)
        for entry in p.glossary:
            glossary_by_term[entry.term] = entry
        deny_tables.extend(p.deny_tables)
        for tc in p.deny_columns:
            deny_columns_by_table.setdefault(tc.table, []).extend(tc.deny_columns)

    return Policy(
        rbac=rbac,
        rls=rls,
        redaction=redaction,
        glossary=list(glossary_by_term.values()),
        deny_tables=_dedupe(deny_tables),
        deny_columns=[
            TableColumns(table=t, deny_columns=_dedupe(cols))
            for t, cols in deny_columns_by_table.items()
        ],
    )


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
