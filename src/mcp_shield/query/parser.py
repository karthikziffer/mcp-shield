"""sqlglot wrapper: parse SQL into an inspectable structure."""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import expressions as exp


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class ParsedQuery:
    sql: str
    dialect: str
    expression: exp.Expression
    tables: tuple[str, ...]
    is_read_only: bool


_WRITE_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.TruncateTable,
)


def parse(sql: str, *, dialect: str = "postgres") -> ParsedQuery:
    """Parse a single SQL statement and return a ParsedQuery.

    Raises ParseError if the input is empty, syntactically invalid, or contains
    multiple statements (a common SQL-injection shape we never want to forward).
    """
    if not sql or not sql.strip():
        raise ParseError("empty SQL")

    try:
        statements = sqlglot.parse(sql, read=dialect)
    except sqlglot.errors.ParseError as e:
        raise ParseError(str(e)) from e

    statements = [s for s in statements if s is not None]
    if len(statements) == 0:
        raise ParseError("no parseable SQL statement")
    if len(statements) > 1:
        raise ParseError("multiple statements are not allowed")

    expression = statements[0]
    tables = tuple(_collect_table_names(expression))
    is_read_only = not isinstance(expression, _WRITE_NODES)

    return ParsedQuery(
        sql=sql,
        dialect=dialect,
        expression=expression,
        tables=tables,
        is_read_only=is_read_only,
    )


def _collect_table_names(expression: exp.Expression) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for table in expression.find_all(exp.Table):
        name = table.name
        if name and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered
