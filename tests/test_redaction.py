"""Output redaction — masking individual values and result rows."""

from mcp_shield import Identity, Policy
from mcp_shield.policy import RedactionRule
from mcp_shield.policy.redaction import mask_value, redact_rows

_IDENTITY = Identity(user_id="u", roles=("analyst",), session_id="s")


def test_mask_email_keeps_first_letter_and_domain():
    assert mask_value("alice@example.com", "email") == "a***@example.com"


def test_mask_email_falls_back_to_full_when_not_email():
    assert mask_value("not-an-email", "email") == "***"


def test_mask_name_initials_each_part():
    assert mask_value("Alice Cooper", "name") == "A. C."


def test_mask_full_returns_stars():
    assert mask_value("anything", "full") == "***"


def test_mask_unknown_falls_back_to_full():
    assert mask_value("x", "no-such-mask") == "***"


def test_mask_passes_none_through():
    assert mask_value(None, "email") is None


def test_redact_rows_applies_per_table_rules():
    policy = Policy(redaction=[
        RedactionRule(table="customers", column="email", mask="email"),
        RedactionRule(table="customers", column="full_name", mask="name"),
    ])
    rows = [{"id": 1, "email": "a@b.com", "full_name": "Alice Cooper", "tier": "gold"}]
    out = redact_rows(rows, table="customers", identity=_IDENTITY, policy=policy)

    assert out[0]["email"] == "a***@b.com"
    assert out[0]["full_name"] == "A. C."
    assert out[0]["tier"] == "gold"


def test_redact_rows_does_not_mutate_input():
    policy = Policy(redaction=[RedactionRule(table="t", column="x", mask="full")])
    rows = [{"x": "secret"}]
    redact_rows(rows, table="t", identity=_IDENTITY, policy=policy)
    assert rows[0]["x"] == "secret"


def test_redact_rows_skips_other_tables():
    policy = Policy(redaction=[RedactionRule(table="customers", column="email", mask="email")])
    rows = [{"email": "a@b.com"}]
    out = redact_rows(rows, table="orders", identity=_IDENTITY, policy=policy)
    assert out[0]["email"] == "a@b.com"


def test_redact_rows_skips_missing_column():
    policy = Policy(redaction=[RedactionRule(table="customers", column="email", mask="email")])
    rows = [{"id": 1}]
    out = redact_rows(rows, table="customers", identity=_IDENTITY, policy=policy)
    assert out == [{"id": 1}]
