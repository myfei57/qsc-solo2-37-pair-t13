"""Tamper-evident ledger for operator commands and control decisions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..core.clock import Clock
from ..errors import ValidationError
from .store import DurableStore, canonical_json

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    entry_id: str
    action: str
    target: str
    detail: str
    cause: str | None
    timestamp: str
    previous_hash: str
    entry_hash: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuditEntry":
        return cls(
            sequence=int(value["sequence"]),
            entry_id=str(value["entry_id"]),
            action=str(value["action"]),
            target=str(value["target"]),
            detail=str(value["detail"]),
            cause=None if value.get("cause") is None else str(value["cause"]),
            timestamp=str(value["timestamp"]),
            previous_hash=str(value["previous_hash"]),
            entry_hash=str(value["entry_hash"]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "entry_id": self.entry_id,
            "action": self.action,
            "target": self.target,
            "detail": self.detail,
            "cause": self.cause,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLedger:
    """Append-only hash chain persisted as a JSON-lines journal."""

    journal = "audit-ledger"

    def __init__(self, store: DurableStore, clock: Clock, limit: int = 5000) -> None:
        self.store = store
        self.clock = clock
        self.limit = limit
        self._entries = [AuditEntry.from_dict(item) for item in store.read_journal(self.journal)]

    @staticmethod
    def digest(entry: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(entry).encode("utf-8")).hexdigest()

    @staticmethod
    def _body(entry: AuditEntry) -> dict[str, Any]:
        """Everything an entry commits to; the hash covers the full body."""

        return {
            "sequence": entry.sequence,
            "entry_id": entry.entry_id,
            "action": entry.action,
            "target": entry.target,
            "detail": entry.detail,
            "cause": entry.cause,
            "timestamp": entry.timestamp,
            "previous_hash": entry.previous_hash,
        }

    def record(
        self,
        action: str,
        target: str,
        detail: str,
        *,
        cause: str | None = None,
    ) -> AuditEntry:
        if not str(action).strip():
            raise ValidationError("audit action must not be empty")
        sequence = 1 if not self._entries else self._entries[-1].sequence + 1
        previous_hash = GENESIS_HASH if not self._entries else self._entries[-1].entry_hash
        body = {
            "sequence": sequence,
            "entry_id": f"aud-{sequence:08d}",
            "action": str(action),
            "target": str(target),
            "detail": str(detail),
            "cause": cause,
            "timestamp": self.clock.timestamp(),
            "previous_hash": previous_hash,
        }
        body["entry_hash"] = self.digest(body)
        entry = AuditEntry(**body)
        self._entries.append(entry)
        self.store.append_journal(self.journal, entry.as_dict(), limit=self.limit)
        if len(self._entries) > self.limit:
            self._entries = self._entries[-self.limit :]
        return entry

    def entries(
        self,
        *,
        target: str | None = None,
        action: str | None = None,
        since: str | None = None,
        limit: int = 200,
    ) -> list[AuditEntry]:
        selected = self._entries
        if target is not None:
            selected = [entry for entry in selected if entry.target == target]
        if action is not None:
            selected = [entry for entry in selected if entry.action == action]
        if since is not None:
            selected = [entry for entry in selected if entry.timestamp >= since]
        return selected[-max(0, limit) :]

    def count(self, action: str | None = None) -> int:
        if action is None:
            return len(self._entries)
        return sum(1 for entry in self._entries if entry.action == action)

    def get(self, entry_id: str) -> AuditEntry | None:
        for entry in reversed(self._entries):
            if entry.entry_id == entry_id:
                return entry
        return None

    def trail(self, entry_id: str) -> list[AuditEntry]:
        """Walk the cause chain back to its root, returned oldest-first."""

        entry = self.get(entry_id)
        if entry is None:
            return []
        by_id = {item.entry_id: item for item in self._entries}
        chain = [entry]
        seen = {entry.entry_id}
        cause = entry.cause
        while cause is not None and cause not in seen:
            parent = by_id.get(cause)
            if parent is None:
                break
            chain.append(parent)
            seen.add(parent.entry_id)
            cause = parent.cause
        chain.reverse()
        return chain

    def targets(self) -> dict[str, dict[str, Any]]:
        counts: dict[str, dict[str, Any]] = {}
        for entry in self._entries:
            item = counts.setdefault(entry.target, {"count": 0, "actions": {}, "latest": entry.timestamp})
            item["count"] += 1
            item["actions"][entry.action] = item["actions"].get(entry.action, 0) + 1
            item["latest"] = entry.timestamp
        return counts

    def verify(self) -> dict[str, Any]:
        """Recompute every hash and check each link against its predecessor."""

        def failure(reason: str, entry: AuditEntry) -> dict[str, Any]:
            return {
                "valid": False,
                "reason": reason,
                "at": entry.entry_id,
                "entries": len(self._entries),
            }

        previous: AuditEntry | None = None
        for entry in self._entries:
            if not entry.entry_hash:
                return failure("missing-hash", entry)
            if entry.entry_hash != self.digest(self._body(entry)):
                return failure("entry-hash-mismatch", entry)
            if previous is None:
                if entry.sequence == 1 and entry.previous_hash != GENESIS_HASH:
                    return failure("chain-break", entry)
            elif entry.sequence != previous.sequence + 1 or entry.previous_hash != previous.entry_hash:
                return failure("chain-break", entry)
            previous = entry
        head = GENESIS_HASH if not self._entries else self._entries[-1].entry_hash
        return {"valid": True, "entries": len(self._entries), "head": head}

    def size(self) -> int:
        return len(self._entries)

    def latest(self) -> AuditEntry | None:
        return None if not self._entries else self._entries[-1]


__all__ = ["GENESIS_HASH", "AuditEntry", "AuditLedger"]
