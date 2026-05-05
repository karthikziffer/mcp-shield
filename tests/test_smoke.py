"""Smoke tests for what's actually implemented in the scaffold."""

from mcp_shield import Policy, Shield


def test_shield_constructs_from_yaml(shield: Shield):
    assert isinstance(shield.policy, Policy)


def test_policy_loads_expected_rules(shield: Shield):
    assert any(rule.role == "analyst" for rule in shield.policy.rbac)
    assert "users_credentials" in shield.policy.deny_tables


def test_lookup_term_returns_glossary_sql(shield: Shield):
    sql = shield.lookup_term("churn")
    assert sql is not None
    assert "cancelled" in sql


def test_lookup_term_unknown_returns_none(shield: Shield):
    assert shield.lookup_term("not_a_real_term") is None


def test_list_terms(shield: Shield):
    assert set(shield.list_terms()) == {"churn", "active_customer"}
