"""Audit log sinks. v0.1 ships JSONL only; Postgres / S3 land when someone asks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class Sink(Protocol):
    async def append(self, record: dict[str, Any]) -> None: ...


class JsonlFileSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    async def append(self, record: dict[str, Any]) -> None:
        raise NotImplementedError
