"""Quick local smoke check — exercises the server's tool logic without MCP transport.

Run from the project root:
    python examples/mcp_server/seed.py
    python examples/mcp_server/_smoke.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))


def show(title: str, result) -> None:
    print(f"\n--- {title} ---")
    if isinstance(result, dict) and "rows" in result:
        print("rewritten:", result.get("rewritten_sql"))
        print("rows:")
        for row in result["rows"]:
            print(" ", row)
    else:
        print(result)


def with_identity(env: dict[str, str]):
    for k in list(os.environ):
        if k.startswith("DEMO_"):
            del os.environ[k]
    os.environ.update(env)
    # Re-import so module-level shield/identity reflect env (server picks identity per call,
    # so we don't actually need to reimport — but we do reset env).
    import importlib
    import server  # noqa: F401
    return importlib.reload(server)


# 1. analyst @ acme — should see only acme customers, with email + name redacted
srv = with_identity({"DEMO_ROLE": "analyst", "DEMO_TENANT_ID": "acme"})
show("analyst@acme: SELECT * FROM customers",
     srv.read_query("SELECT id, full_name, email, tier FROM customers"))

# 2. analyst @ globex — same query, only globex rows
srv = with_identity({"DEMO_ROLE": "analyst", "DEMO_TENANT_ID": "globex"})
show("analyst@globex: same query",
     srv.read_query("SELECT id, full_name, email, tier FROM customers"))

# 3. support @ us — orders scoped to us
srv = with_identity({"DEMO_ROLE": "support", "DEMO_REGION": "us"})
show("support@us: SELECT * FROM orders",
     srv.read_query("SELECT * FROM orders"))

# 4. support tries products — not in their allow_tables
show("support@us: SELECT * FROM products (denied)",
     srv.read_query("SELECT * FROM products"))

# 5. anyone tries users_credentials — globally denied
srv = with_identity({"DEMO_ROLE": "analyst", "DEMO_TENANT_ID": "acme"})
show("analyst: SELECT * FROM users_credentials (denied)",
     srv.read_query("SELECT * FROM users_credentials"))

# 6. write blocked
show("analyst: UPDATE customers (write blocked)",
     srv.read_query("UPDATE customers SET email = NULL"))

# 7. tools without RBAC entry
show("list_tables (analyst)", srv.list_tables())
show("glossary lookup", srv.lookup_business_term("high_value"))
show("unknown glossary term", srv.lookup_business_term("not_a_term"))
