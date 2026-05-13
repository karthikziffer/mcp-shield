"""FastMCP server demonstrating mcp-shield in front of a SQLite database.

Run from the project root after seeding:
    python examples/mcp_server/seed.py
    DEMO_ROLE=analyst DEMO_TENANT_ID=acme \\
        python examples/mcp_server/server.py

Identity is read from environment variables for the demo. In a real deployment
you'd derive it from the request's auth headers via the FastMCP Context.

Try it via mcp-inspector:
    npx @modelcontextprotocol/inspector \\
        python examples/mcp_server/server.py
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_shield import AccessDenied, Identity, Shield, ValidationError
from mcp_shield.query import parse
from mcp_shield.query.parser import ParseError

HERE = Path(__file__).parent
DB_PATH = HERE / "shield_demo.sqlite"
POLICY_PATH = HERE / "policies.yaml"

shield = Shield.from_yaml(POLICY_PATH, dialect="sqlite", default_limit=50)
mcp = FastMCP("mcp-shield-demo")


def _identity() -> Identity:
    role = os.environ.get("DEMO_ROLE", "analyst")
    user_id = os.environ.get("DEMO_USER_ID", f"demo-{role}")
    claims: dict[str, Any] = {}
    if "DEMO_TENANT_ID" in os.environ:
        claims["tenant_id"] = os.environ["DEMO_TENANT_ID"]
    if "DEMO_REGION" in os.environ:
        claims["region"] = os.environ["DEMO_REGION"]
    return Identity(user_id=user_id, roles=(role,), session_id="demo-session", claims=claims)


def _connect() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise RuntimeError(f"database not found — run examples/mcp_server/seed.py first")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@mcp.tool()
def read_query(sql: str) -> dict[str, Any]:
    """Run a read-only SQL query through the shield.

    The shield (1) checks tool access, (2) rewrites the SQL to inject the
    caller's RLS predicate and cap LIMIT, (3) lets sqlite run it, and
    (4) redacts sensitive columns from the result.
    """
    identity = _identity()
    try:
        shield.check_tool(identity, "read_query")
        safe_sql = shield.rewrite(sql, identity)
        parsed = parse(sql, dialect="sqlite")
    except (AccessDenied, ValidationError, ParseError) as e:
        return {"error": type(e).__name__, "message": str(e)}

    with _connect() as conn:
        rows = [dict(r) for r in conn.execute(safe_sql).fetchall()]

    for table in parsed.tables:
        rows = shield.redact(rows, table, identity)

    return {
        "rewritten_sql": safe_sql,
        "row_count": len(rows),
        "rows": rows,
    }


@mcp.tool()
def list_tables() -> dict[str, Any]:
    """Return the tables this identity is allowed to read."""
    identity = _identity()
    try:
        shield.check_tool(identity, "list_tables")
    except AccessDenied as e:
        return {"error": "AccessDenied", "message": str(e)}

    role_set = set(identity.roles)
    denied = set(shield.policy.deny_tables)
    allowed: set[str] = set()
    for rule in shield.policy.rbac:
        if rule.role in role_set:
            allowed.update(rule.allow_tables)
    return {"tables": sorted(allowed - denied)}


@mcp.tool()
def lookup_business_term(term: str) -> dict[str, Any]:
    """Resolve a business term (e.g. 'high_value') to its SQL fragment."""
    identity = _identity()
    try:
        shield.check_tool(identity, "lookup_business_term")
    except AccessDenied as e:
        return {"error": "AccessDenied", "message": str(e)}

    sql = shield.lookup_term(term)
    if sql is None:
        return {"term": term, "sql": None, "known_terms": shield.list_terms()}
    return {"term": term, "sql": sql}


if __name__ == "__main__":
    mcp.run()
