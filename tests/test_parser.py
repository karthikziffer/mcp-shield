"""SQL parsing — table extraction, read/write detection, error cases."""

import pytest

from mcp_shield.query.parser import ParseError, parse


def test_parse_extracts_tables_in_order():
    p = parse("SELECT id FROM customers c JOIN orders o ON o.customer_id = c.id")
    assert p.tables == ("customers", "orders")
    assert p.is_read_only is True


def test_parse_marks_writes_non_read_only():
    assert parse("UPDATE customers SET email = NULL").is_read_only is False
    assert parse("DELETE FROM customers").is_read_only is False
    assert parse("INSERT INTO customers (id) VALUES (1)").is_read_only is False


def test_parse_rejects_multiple_statements():
    with pytest.raises(ParseError, match="multiple"):
        parse("SELECT 1; DROP TABLE users")


def test_parse_rejects_empty():
    with pytest.raises(ParseError, match="empty"):
        parse("")


def test_parse_rejects_invalid_sql():
    with pytest.raises(ParseError):
        parse("NOT SQL!!!")


def test_parse_dedupes_repeated_table_references():
    p = parse("SELECT a.id FROM customers a JOIN customers b ON a.parent = b.id")
    assert p.tables == ("customers",)
