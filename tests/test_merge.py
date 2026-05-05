"""Policy merge + dynamic extension semantics."""

from pathlib import Path

import pytest

from mcp_shield import Policy, Shield, merge_policies
from mcp_shield.policy import (
    GlossaryEntry,
    RBACRule,
    RedactionRule,
    RLSRule,
    TableColumns,
)


def test_merge_empty_returns_empty_policy():
    merged = merge_policies()
    assert merged.rbac == []
    assert merged.glossary == []


def test_merge_concatenates_rule_lists():
    a = Policy(rbac=[RBACRule(role="analyst", allow_tools=["read_query"])])
    b = Policy(rbac=[RBACRule(role="support", allow_tools=["read_query"])])

    merged = merge_policies(a, b)

    assert {r.role for r in merged.rbac} == {"analyst", "support"}


def test_merge_glossary_later_wins():
    a = Policy(glossary=[GlossaryEntry(term="churn", sql="OLD_DEFINITION")])
    b = Policy(glossary=[GlossaryEntry(term="churn", sql="NEW_DEFINITION")])

    merged = merge_policies(a, b)

    assert len(merged.glossary) == 1
    assert merged.glossary[0].sql == "NEW_DEFINITION"


def test_merge_deny_tables_union_no_dupes():
    a = Policy(deny_tables=["users_credentials", "audit_internal"])
    b = Policy(deny_tables=["audit_internal", "secrets"])

    merged = merge_policies(a, b)

    assert merged.deny_tables == ["users_credentials", "audit_internal", "secrets"]


def test_merge_deny_columns_combine_per_table():
    a = Policy(deny_columns=[TableColumns(table="users", deny_columns=["password_hash"])])
    b = Policy(deny_columns=[
        TableColumns(table="users", deny_columns=["mfa_secret", "password_hash"]),
    ])

    merged = merge_policies(a, b)

    by_table = {tc.table: tc.deny_columns for tc in merged.deny_columns}
    assert by_table["users"] == ["password_hash", "mfa_secret"]


def test_merge_preserves_rls_and_redaction_lists():
    a = Policy(rls=[RLSRule(role="analyst", table="customers", predicate="t = 1")])
    b = Policy(redaction=[RedactionRule(table="customers", column="email", mask="email")])

    merged = merge_policies(a, b)

    assert len(merged.rls) == 1
    assert len(merged.redaction) == 1


def test_shield_from_yaml_multi_file_merges(tmp_path: Path, example_policy_path: Path):
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(
        "rbac:\n"
        "  - role: oncall\n"
        "    allow_tools: [read_query]\n"
        "glossary:\n"
        "  - term: churn\n"
        "    sql: OVERRIDDEN\n"
    )

    shield = Shield.from_yaml(example_policy_path, overlay)

    roles = {r.role for r in shield.policy.rbac}
    assert {"analyst", "support", "oncall"} <= roles
    assert shield.lookup_term("churn") == "OVERRIDDEN"


def test_shield_from_yaml_requires_at_least_one_path():
    with pytest.raises(ValueError):
        Shield.from_yaml()


def test_shield_extend_adds_rules_at_runtime(shield: Shield):
    assert shield.lookup_term("mrr") is None

    shield.extend(Policy(
        glossary=[GlossaryEntry(term="mrr", sql="SUM(amount)")],
        rbac=[RBACRule(role="finance", allow_tools=["read_query"])],
    ))

    assert shield.lookup_term("mrr") == "SUM(amount)"
    assert any(r.role == "finance" for r in shield.policy.rbac)
