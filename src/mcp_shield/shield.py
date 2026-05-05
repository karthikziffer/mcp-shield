"""mcp-shield's public facade. Compose the policy primitives behind a single
object that host MCP servers call from inside their own tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .identity import Identity
from .policy import Policy, load_policy, merge_policies
from .policy import glossary as _glossary
from .policy import rbac as _rbac
from .policy import redaction as _redaction
from .policy import rls as _rls
from .query import parse, rewrite, validate

Row = dict[str, Any]


class Shield:
    def __init__(
        self,
        policy: Policy,
        *,
        default_limit: int = 100,
        allowed_functions: set[str] | None = None,
        dialect: str = "postgres",
    ) -> None:
        self._policy = policy
        self._default_limit = default_limit
        self._allowed_functions = allowed_functions or set()
        self._dialect = dialect

    @classmethod
    def from_yaml(cls, *paths: str | Path, **kwargs: Any) -> Shield:
        """Load one or more policy YAML files and merge them (later files override
        earlier glossary terms; rule lists concatenate; deny-lists union)."""
        if not paths:
            raise ValueError("Shield.from_yaml requires at least one path")
        loaded = [load_policy(Path(p)) for p in paths]
        return cls(merge_policies(*loaded), **kwargs)

    @property
    def policy(self) -> Policy:
        return self._policy

    def extend(self, other: Policy) -> None:
        """Merge additional rules into the live policy. Intended for startup-time
        composition; not safe to call concurrently with rewrite/redact."""
        self._policy = merge_policies(self._policy, other)

    def check_tool(self, identity: Identity, tool_name: str) -> None:
        _rbac.check_tool(identity, tool_name, self._policy)

    def rewrite(self, sql: str, identity: Identity) -> str:
        parsed = parse(sql, dialect=self._dialect)
        _rbac.check_tables(identity, list(parsed.tables), self._policy)
        validate(parsed, allowed_functions=self._allowed_functions, allow_writes=False)
        predicates = _rls.predicates_for(identity, list(parsed.tables), self._policy)
        return rewrite(
            parsed,
            rls_predicates=predicates,
            deny_columns=self._deny_columns_index(),
            default_limit=self._default_limit,
        )

    def redact(self, rows: list[Row], table: str, identity: Identity) -> list[Row]:
        return _redaction.redact_rows(rows, table=table, identity=identity, policy=self._policy)

    def lookup_term(self, term: str) -> str | None:
        return _glossary.lookup(term, self._policy)

    def list_terms(self) -> list[str]:
        return _glossary.list_terms(self._policy)

    def _deny_columns_index(self) -> dict[str, list[str]]:
        return {tc.table: list(tc.deny_columns) for tc in self._policy.deny_columns}
