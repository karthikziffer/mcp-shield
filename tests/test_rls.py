"""RLS — predicate selection and claim substitution."""

import pytest

from mcp_shield import Identity, Policy
from mcp_shield.policy import RLSRule
from mcp_shield.policy.rls import MissingClaim, predicates_for


def _id(*roles: str, **claims: object) -> Identity:
    return Identity(user_id="u", roles=roles, session_id="s", claims=claims)


def test_predicate_substitutes_claim():
    policy = Policy(rls=[RLSRule(
        role="analyst", table="customers",
        predicate="tenant_id = '{identity.claims[tenant_id]}'",
    )])
    out = predicates_for(_id("analyst", tenant_id="acme"), ["customers"], policy)
    assert out == {"customers": "tenant_id = 'acme'"}


def test_predicate_escapes_single_quotes_in_claim():
    policy = Policy(rls=[RLSRule(
        role="analyst", table="customers",
        predicate="tenant_id = '{identity.claims[tenant_id]}'",
    )])
    out = predicates_for(_id("analyst", tenant_id="ac'me"), ["customers"], policy)
    assert out["customers"] == "tenant_id = 'ac''me'"


def test_predicate_skipped_for_unrequested_table():
    policy = Policy(rls=[RLSRule(
        role="analyst", table="customers", predicate="x = 1",
    )])
    assert predicates_for(_id("analyst"), ["orders"], policy) == {}


def test_predicate_skipped_for_unmatched_role():
    policy = Policy(rls=[RLSRule(
        role="analyst", table="customers", predicate="x = 1",
    )])
    assert predicates_for(_id("support"), ["customers"], policy) == {}


def test_predicate_combines_multiple_role_rules_with_or():
    policy = Policy(rls=[
        RLSRule(role="analyst", table="customers", predicate="region = 'us'"),
        RLSRule(role="ops", table="customers", predicate="region = 'eu'"),
    ])
    out = predicates_for(_id("analyst", "ops"), ["customers"], policy)
    assert out["customers"] == "(region = 'us') OR (region = 'eu')"


def test_predicate_missing_claim_raises():
    policy = Policy(rls=[RLSRule(
        role="analyst", table="customers",
        predicate="tenant_id = '{identity.claims[tenant_id]}'",
    )])
    with pytest.raises(MissingClaim, match="tenant_id"):
        predicates_for(_id("analyst"), ["customers"], policy)
