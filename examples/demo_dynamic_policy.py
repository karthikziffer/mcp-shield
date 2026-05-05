"""Demo: composing mcp-shield policies from multiple sources at runtime.

Run from the project root:
    python examples/demo_dynamic_policy.py
"""

from pathlib import Path

from mcp_shield import Policy, Shield
from mcp_shield.policy import GlossaryEntry, RBACRule

HERE = Path(__file__).parent


def banner(title: str) -> None:
    print(f"\n{'=' * 60}\n {title}\n{'=' * 60}")


def show_state(shield: Shield) -> None:
    p = shield.policy
    print(f"  roles:        {sorted({r.role for r in p.rbac})}")
    print(f"  deny_tables:  {p.deny_tables}")
    print(f"  glossary:     {sorted(shield.list_terms())}")
    print(f"  churn def:    {shield.lookup_term('churn')}")


banner("1. Base policy only")
shield = Shield.from_yaml(HERE / "policies.yaml")
show_state(shield)

banner("2. Base + production overlay (multi-file load)")
shield = Shield.from_yaml(
    HERE / "policies.yaml",
    HERE / "overlay_production.yaml",
)
show_state(shield)
print("  -> 'oncall' role added; 'churn' redefined; 'mrr' added;")
print("     deny_tables unioned (no duplicates).")

banner("3. Extend at runtime from code (e.g. from your own settings)")
shield.extend(Policy(
    rbac=[RBACRule(role="finance", allow_tools=["read_query"], allow_tables=["orders"])],
    glossary=[GlossaryEntry(term="arr", sql="SUM(amount) * 12")],
))
show_state(shield)
print("  -> 'finance' role and 'arr' glossary term added live.")

banner("4. What still needs implementation")
print("  shield.rewrite(...)    -> NotImplementedError (parser/rewriter stubs)")
print("  shield.redact(...)     -> NotImplementedError (redaction stub)")
print("  shield.check_tool(...) -> NotImplementedError (rbac stub)")
print()
print("  Working today: Shield.from_yaml(*paths), shield.extend(),")
print("                 shield.lookup_term(), shield.list_terms(), shield.policy")
