<p align="center">
  <img src="docs/banner.svg" alt="mcp-shield — security primitives for MCP servers" width="100%"/>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
  <img src="https://img.shields.io/badge/coverage-83%25-yellowgreen.svg" alt="Coverage 83%"/>
  <img src="https://img.shields.io/badge/tests-14%20passing-brightgreen.svg" alt="14 tests passing"/>
  <img src="https://img.shields.io/badge/status-pre--alpha-orange.svg" alt="Status: pre-alpha"/>
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
