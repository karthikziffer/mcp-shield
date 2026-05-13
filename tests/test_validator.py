"""SQL validator — write blocking and function whitelist."""

import pytest

from mcp_shield.query.parser import parse
from mcp_shield.query.validator import ValidationError, validate


def test_validate_blocks_writes_by_default():
    with pytest.raises(ValidationError, match="write"):
        validate(parse("UPDATE customers SET email = NULL"), allowed_functions=set())


def test_validate_allows_writes_when_opted_in():
    validate(
        parse("UPDATE customers SET email = NULL"),
        allowed_functions=set(),
        allow_writes=True,
    )


def test_validate_empty_whitelist_allows_any_function():
    validate(parse("SELECT pg_sleep(5)"), allowed_functions=set())


def test_validate_blocks_function_outside_whitelist():
    with pytest.raises(ValidationError, match="pg_sleep"):
        validate(parse("SELECT pg_sleep(5)"), allowed_functions={"count", "sum"})


def test_validate_allows_whitelisted_function():
    validate(parse("SELECT COUNT(*) FROM orders"), allowed_functions={"count"})


def test_validate_function_match_is_case_insensitive():
    validate(parse("SELECT count(*) FROM orders"), allowed_functions={"COUNT"})
