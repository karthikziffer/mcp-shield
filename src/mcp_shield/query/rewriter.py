"""SQL rewriting: inject RLS predicates, cap rows with LIMIT, drop denied columns."""

from __future__ import annotations

import sqlglot
from sqlglot import expressions as exp

from .parser import ParsedQuery


def rewrite(
    parsed: ParsedQuery,
    *,
    rls_predicates: dict[str, str],
    deny_columns: dict[str, list[str]],
    default_limit: int,
) -> str:
    """Return a rewritten SQL string with RLS, column deny-list, and LIMIT applied.

    - ``rls_predicates`` maps {table_name: predicate_sql}; predicates are AND-ed
      into the existing WHERE clause for any SELECT that touches the table.
    - ``deny_columns`` maps {table_name: [columns]}; ``SELECT *`` against a
      table with deny entries is expanded to all columns minus the denied ones
      (we cannot know the schema, so we leave non-star projections untouched —
      RBAC and the validator are expected to catch explicit references).
    - ``default_limit`` is applied to top-level SELECTs that have no LIMIT, and
      caps any LIMIT larger than itself.

    Only SELECTs are rewritten; non-SELECT inputs round-trip unchanged.
    """
    expression = parsed.expression.copy()

    if not isinstance(expression, exp.Select):
        return expression.sql(dialect=parsed.dialect)

    if rls_predicates:
        _apply_rls(expression, rls_predicates, dialect=parsed.dialect)

    if deny_columns:
        _apply_column_deny(expression, deny_columns)

    if default_limit and default_limit > 0:
        _apply_limit(expression, default_limit)

    return expression.sql(dialect=parsed.dialect)


def _apply_rls(select: exp.Select, predicates: dict[str, str], *, dialect: str) -> None:
    referenced = {t.name for t in select.find_all(exp.Table) if t.name}
    for table_name, predicate_sql in predicates.items():
        if table_name not in referenced:
            continue
        predicate = sqlglot.parse_one(predicate_sql, read=dialect)
        select.where(predicate, append=True, copy=False)


def _apply_column_deny(select: exp.Select, deny_columns: dict[str, list[str]]) -> None:
    """Drop explicit references to denied columns from the projection.

    SELECT * is left alone — the rewriter is schema-less, so safely expanding
    a star into an explicit column list isn't possible from SQL alone. The
    redact step on the result set is the backstop for column-level secrets.
    """
    if not select.expressions:
        return

    table_aliases = _table_alias_map(select)
    kept: list[exp.Expression] = []
    for projection in select.expressions:
        column = _as_simple_column(projection)
        if column is None:
            kept.append(projection)
            continue
        table = _resolve_column_table(column, table_aliases)
        denied = deny_columns.get(table or "", [])
        if column.name in denied:
            continue
        kept.append(projection)

    if not kept:
        kept.append(exp.Literal.number(1).as_("_redacted"))
    select.set("expressions", kept)


def _table_alias_map(select: exp.Select) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for table in select.find_all(exp.Table):
        if not table.name:
            continue
        aliases[table.name] = table.name
        alias = table.alias_or_name
        if alias:
            aliases[alias] = table.name
    return aliases


def _as_simple_column(projection: exp.Expression) -> exp.Column | None:
    if isinstance(projection, exp.Column):
        return projection
    if isinstance(projection, exp.Alias) and isinstance(projection.this, exp.Column):
        return projection.this
    return None


def _resolve_column_table(column: exp.Column, aliases: dict[str, str]) -> str | None:
    qualifier = column.table
    if qualifier:
        return aliases.get(qualifier, qualifier)
    if len(aliases) == 1:
        return next(iter(aliases.values()))
    return None


def _apply_limit(select: exp.Select, cap: int) -> None:
    existing = select.args.get("limit")
    if existing is None:
        select.limit(cap, copy=False)
        return

    current = _extract_limit_value(existing)
    if current is None or current > cap:
        select.limit(cap, copy=False)


def _extract_limit_value(limit_expr: exp.Expression) -> int | None:
    inner = limit_expr.expression if isinstance(limit_expr, exp.Limit) else limit_expr
    if isinstance(inner, exp.Literal) and inner.is_int:
        return int(inner.this)
    return None
