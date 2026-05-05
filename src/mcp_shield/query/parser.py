"""sqlglot wrapper: parse SQL into an inspectable structure."""

from __future__ import annotations

from dataclasses import dataclass

from sqlglot import expressions as exp


@dataclass(frozen=True)
class ParsedQuery:
    sql: str
    dialect: str
    expression: exp.Expression
    tables: tuple[str, ...]
    is_read_only: bool


def parse(sql: str, *, dialect: str = "postgres") -> ParsedQuery:
    raise NotImplementedError
