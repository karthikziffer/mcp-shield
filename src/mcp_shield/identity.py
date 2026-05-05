"""The Identity object passed into every Shield call. The host application is
responsible for constructing it (from a JWT, session, header, etc.)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Identity:
    user_id: str
    roles: tuple[str, ...]
    session_id: str
    claims: dict[str, Any] = field(default_factory=dict)
