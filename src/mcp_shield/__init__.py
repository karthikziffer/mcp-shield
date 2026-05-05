"""Security primitives for MCP servers."""

from .identity import Identity
from .policy import Policy, load_policy, merge_policies
from .policy.rbac import AccessDenied
from .query import ValidationError
from .shield import Shield

__version__ = "0.0.1"

__all__ = [
    "AccessDenied",
    "Identity",
    "Policy",
    "Shield",
    "ValidationError",
    "load_policy",
    "merge_policies",
]
