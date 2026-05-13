"""SQL rewriter — RLS injection, column deny, LIMIT cap."""

from mcp_shield.query.parser import parse
from mcp_shield.query.rewriter import rewrite


def _rewrite(sql: str, **kwargs) -> str:
    kwargs.setdefault("rls_predicates", {})
    kwargs.setdefault("deny_columns", {})
    kwargs.setdefault("default_limit", 100)
    return rewrite(parse(sql), **kwargs)


def test_rewrite_injects_rls_into_bare_select():
    out = _rewrite(
        "SELECT id FROM customers",
        rls_predicates={"customers": "tenant_id = 'acme'"},
    )
    assert "tenant_id = 'acme'" in out
    assert "WHERE" in out


def test_rewrite_appends_rls_to_existing_where():
    out = _rewrite(
        "SELECT id FROM customers WHERE active = true",
        rls_predicates={"customers": "tenant_id = 'acme'"},
    )
    assert "active = TRUE AND tenant_id = 'acme'" in out


def test_rewrite_skips_rls_for_unreferenced_tables():
    out = _rewrite(
        "SELECT id FROM orders",
        rls_predicates={"customers": "tenant_id = 'acme'"},
    )
    assert "tenant_id" not in out


def test_rewrite_drops_explicit_denied_columns():
    out = _rewrite(
        "SELECT id, password_hash, email FROM users",
        deny_columns={"users": ["password_hash"]},
    )
    assert "password_hash" not in out
    assert "id" in out and "email" in out


def test_rewrite_keeps_select_star_unchanged():
    out = _rewrite(
        "SELECT * FROM users",
        deny_columns={"users": ["password_hash"]},
    )
    assert "*" in out


def test_rewrite_applies_default_limit_when_missing():
    out = _rewrite("SELECT id FROM orders")
    assert "LIMIT 100" in out


def test_rewrite_caps_oversized_limit():
    out = _rewrite("SELECT id FROM orders LIMIT 10000")
    assert "LIMIT 100" in out
    assert "10000" not in out


def test_rewrite_keeps_smaller_limit():
    out = _rewrite("SELECT id FROM orders LIMIT 10")
    assert "LIMIT 10" in out


def test_rewrite_passes_through_non_select():
    out = _rewrite(
        "UPDATE customers SET email = NULL",
        rls_predicates={"customers": "tenant_id = 'acme'"},
    )
    assert "tenant_id" not in out
    assert out.upper().startswith("UPDATE")
