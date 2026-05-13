<p align="center">
  <img src="docs/banner.svg" alt="mcp-shield — security primitives for MCP servers" width="100%"/>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
  <img src="https://img.shields.io/badge/coverage-88%25-yellowgreen.svg" alt="Coverage 88%"/>
  <img src="https://img.shields.io/badge/tests-59%20passing-brightgreen.svg" alt="59 tests passing"/>
  <img src="https://img.shields.io/badge/status-alpha-orange.svg" alt="Status: alpha"/>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/code%20style-ruff-261230.svg" alt="Code style: ruff"/></a>
</p>

# mcp-shield

Security primitives for MCP servers. **You write the MCP server; mcp-shield gives you the security layer.**

Exposing a database directly to an MCP server bypasses the access controls and observability your application normally provides, creating both security and performance risk. mcp-shield sits between the MCP server and the database to enforce role-based access control, row-level filters, output redaction, and audit logging.

## Install

Not yet on PyPI. Install directly from GitHub:

```bash
pip install git+https://github.com/karthikziffer/mcp-shield.git
```

Only `pydantic`, `sqlglot`, and `pyyaml` are required. No web framework, no database client.

## Use it

```python
from mcp_shield import Shield, Identity

shield = Shield.from_yaml("policies.yaml")

# Inside your MCP tool handler:
async def read_query(sql: str, ctx) -> list[dict]:
    identity = my_identity_from(ctx)             # your job
    shield.check_tool(identity, "read_query")    # raises AccessDenied
    safe_sql = shield.rewrite(sql, identity)     # raises if denied
    rows = await my_db.fetch(safe_sql)           # your DB connection
    return shield.redact(rows, "customers", identity)
```

That's the whole integration. Three calls: `check_tool`, `rewrite`, `redact`.

## Composing policies

Load multiple files (base + environment + tenant overrides):

```python
shield = Shield.from_yaml("base.yaml", "production.yaml", "tenant-acme.yaml")
```

Or add rules at runtime from your own config:

```python
from mcp_shield import Policy
from mcp_shield.policy import RBACRule, GlossaryEntry

shield.extend(Policy(
    rbac=[RBACRule(role="oncall", allow_tools=["read_query"])],
    glossary=[GlossaryEntry(term="mrr", sql="SUM(amount)")],
))
```

Merge semantics: rule lists concatenate, glossary terms are later-wins, deny-lists union.

## What's in the box

| Primitive | Method | What it does |
|---|---|---|
| RBAC | `check_tool`, indirectly via `rewrite` | Reject tool calls and table reads not allowed for the identity's roles |
| Query rewriting | `rewrite` | Inject row-level predicates, drop denied columns, cap rows with `LIMIT` |
| Validation | (inside `rewrite`) | Block disallowed SQL functions, write statements, structural injection patterns |
| Output redaction | `redact` | Mask sensitive columns in result sets (email, name, custom) |
| Glossary | `lookup_term`, `list_terms` | Map business terms ("churn") to SQL fragments |
| Audit | `mcp_shield.audit.AuditLog` + `Sink` | Append-only event log; pluggable sink |

## Policy file

See `examples/policies.yaml` for the full schema. In short:

```yaml
deny_tables: [users_credentials]
deny_columns:
  - table: users
    deny_columns: [password_hash]
rbac:
  - role: analyst
    allow_tools: [read_query]
    allow_tables: [orders, customers]
rls:
  - role: analyst
    table: customers
    predicate: "tenant_id = '{identity.claims[tenant_id]}'"
redaction:
  - table: customers
    column: email
    mask: email
glossary:
  - term: churn
    sql: "status = 'cancelled' AND last_login_at < NOW() - INTERVAL '30 days'"
```

## Try it end-to-end

`examples/mcp_server/_smoke.py` runs the demo FastMCP server's tool functions in-process against a seeded SQLite DB across 7 scenarios — exercising RBAC, RLS, redaction, and the validator in one pass.

| Scenario in `_smoke.py` | Primitive exercised |
|---|---|
| 1 — analyst@acme `SELECT customers` | RLS (`tenant_id=acme`) + redaction (email, name) |
| 2 — analyst@globex same query | RLS with different claim |
| 3 — support@us `SELECT orders` | RLS (`region=us`) |
| 4 — support tries products | RBAC (table not in `allow_tables`) |
| 5 — analyst tries users_credentials | RBAC (globally denied) |
| 6 — `UPDATE customers` | Validator (write blocked) |
| 7 — `list_tables` / glossary lookup | Tool RBAC + glossary |

Run from the repo root:

```bash
pip install -e ".[dev]"
pip install "mcp[cli]"          # FastMCP runtime — not in declared deps
python examples/mcp_server/seed.py
python examples/mcp_server/_smoke.py
```

Expected output (rewritten SQL shows RLS injection + LIMIT cap; rows show redaction):

```
--- analyst@acme: SELECT * FROM customers ---
rewritten: SELECT id, full_name, email, tier FROM customers WHERE tenant_id = 'acme' LIMIT 50
rows:
  {'id': 1, 'full_name': 'A. C.', 'email': 'a***@acme.test', 'tier': 'gold'}
  {'id': 2, 'full_name': 'B. M.', 'email': 'b***@acme.test', 'tier': 'silver'}

--- analyst@globex: same query ---
rewritten: SELECT id, full_name, email, tier FROM customers WHERE tenant_id = 'globex' LIMIT 50
rows:
  {'id': 3, 'full_name': 'C. D.', 'email': 'c***@globex.test', 'tier': 'gold'}
  {'id': 4, 'full_name': 'D. B.', 'email': 'd***@globex.test', 'tier': 'silver'}

--- support@us: SELECT * FROM orders ---
rewritten: SELECT * FROM orders WHERE region = 'us' LIMIT 50
rows:
  {'id': 1, 'customer_id': 1, 'region': 'us', 'amount': 199.0, 'status': 'completed'}
  {'id': 2, 'customer_id': 1, 'region': 'us', 'amount': 49.0, 'status': 'completed'}
  {'id': 3, 'customer_id': 2, 'region': 'us', 'amount': 19.0, 'status': 'cancelled'}

--- support@us: SELECT * FROM products (denied) ---
{'error': 'AccessDenied', 'message': "table 'products' is not in allow_tables for roles ['support']"}

--- analyst: SELECT * FROM users_credentials (denied) ---
{'error': 'AccessDenied', 'message': "table 'users_credentials' is globally denied"}

--- analyst: UPDATE customers (write blocked) ---
{'error': 'ValidationError', 'message': 'write statements are not allowed'}

--- list_tables (analyst) ---
{'tables': ['customers', 'orders', 'products']}

--- glossary lookup ---
{'term': 'high_value', 'sql': "tier = 'gold'"}

--- unknown glossary term ---
{'term': 'not_a_term', 'sql': None, 'known_terms': ['high_value', 'completed_orders']}
```

## Try it with MCP Inspector

For interactive exploration, run the demo server under [`@modelcontextprotocol/inspector`](https://github.com/modelcontextprotocol/inspector). Each tool accepts optional `role`, `tenant_id`, and `region` arguments so you can switch identity per call without restarting the server.

```bash
python examples/mcp_server/seed.py
npx @modelcontextprotocol/inspector python examples/mcp_server/server.py
```

Or set defaults at launch with env vars (`DEMO_ROLE`, `DEMO_TENANT_ID`, `DEMO_REGION`) — per-call args still override them:

```bash
DEMO_ROLE=support DEMO_REGION=eu \
  npx @modelcontextprotocol/inspector python examples/mcp_server/server.py
```

In the Inspector UI, call `read_query` with these argument combinations to exercise each primitive:

| `sql` | `role` | `tenant_id` | `region` | What it shows |
|---|---|---|---|---|
| `SELECT id, full_name, email, tier FROM customers` | `analyst` | `acme` | — | RLS injects `WHERE tenant_id='acme'`; email + name redacted |
| same | `analyst` | `globex` | — | Same query, different tenant slice |
| `SELECT * FROM orders` | `support` | — | `us` | RLS injects `WHERE region='us'` |
| `SELECT * FROM orders` | `support` | — | `eu` | Same, eu rows only |
| `SELECT * FROM products` | `support` | — | `us` | `AccessDenied` — not in support's `allow_tables` |
| `SELECT * FROM users_credentials` | `analyst` | `acme` | — | `AccessDenied` — globally denied |
| `UPDATE customers SET email = NULL` | `analyst` | `acme` | — | `ValidationError` — writes blocked |
| `SELECT * FROM orders LIMIT 1000` | `analyst` | `acme` | — | LIMIT capped to 50 |
| `SELECT * FROM customers` | `analyst` | *(omit)* | — | `MissingClaim` — RLS placeholder unfilled |
| `SELECT * FROM customers` | `admin` | `acme` | — | `AccessDenied` — unknown role |

`list_tables` and `lookup_business_term` accept the same identity arguments. Try `lookup_business_term(term="high_value")` and `term="completed_orders"` to see glossary entries from `examples/mcp_server/policies.yaml`.

> **Demo-only pattern.** Accepting identity from caller arguments is unsafe in production — a malicious client could claim any role. A real deployment derives `Identity` from authenticated request context (headers, session, JWT) via the FastMCP `Context` object.

## Develop

```bash
pip install -e ".[dev]"
pytest                                    # 14 tests
pytest --cov=mcp_shield                   # coverage report
ruff check src tests
```

The coverage badge above is static. Once CI is set up (GitHub Actions → Codecov / Coveralls), swap it for a dynamic badge such as `https://img.shields.io/codecov/c/github/<org>/mcp-shield`.

## Layout

```
src/mcp_shield/
  shield.py         The public Shield facade
  identity.py       The Identity dataclass (host app constructs it)
  policy/           RBAC, RLS, redaction, glossary, deny-lists + YAML loader
  query/            Parse, validate, rewrite SQL with sqlglot
  audit/            Append-only audit log + Sink protocol
```
