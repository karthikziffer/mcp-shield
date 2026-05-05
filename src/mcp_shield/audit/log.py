"""Append-only audit event writer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .sinks import Sink


@dataclass(frozen=True)
class AuditEvent:
    timestamp: datetime
    user_id: str
    session_id: str
    tool: str
    raw_input: dict[str, Any]
    rewritten_sql: str | None
    outcome: str
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    def __init__(self, sink: Sink) -> None:
        self._sink = sink

    async def write(self, event: AuditEvent) -> None:
        raise NotImplementedError
