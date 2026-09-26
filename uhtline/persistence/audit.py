"""Tamper-evident ledger for operator commands and control decisions.

Every entry seals itself with a hash over *all* of its own fields, including
the hash of the entry immediately before it and the id of the entry that
causally triggered it.  Two independent edges therefore run through the
journal:

* ``previous_hash`` -- the temporal backbone: each entry interlocks with the
  entry written directly before it, so altering, deleting or inserting a
  record breaks the seal of every record that follows;
* ``cause`` -- the causal edge: the triggering audit entry, so a record can
  be traced back through "what caused this" rather than just "what came
  before it".

``verify()`` recomputes the whole backbone; ``trace()`` walks the causal
edges.  Writers may use :meth:`AuditLedger.causation` (or have one opened for
the duration of a control command) so that entries emitted by one triggered
action are threaded onto the entry that triggered it automatically.
"""

from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator

from ..core.clock import Clock
from ..errors import LedgerIntegrityError, ValidationError
from .store import DurableStore, canonical_json

GENESIS_HASH = "0" * 64

# Fields sealed by ``entry_hash`` -- every persisted field except the seal.
SEALED_FIELDS: tuple[str, ...] = (
    "sequence",
    "entry_id",
    "action",
    "target",
    "detail",
    "cause",
    "timestamp",
    "previous_hash",
)


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


@dataclass(frozen=True)
class CausalTrace:
    """Result of walking the ``cause`` edges backwards from one entry."""

    start_id: str
    entries: list[AuditEntry]
    root_id: str | None
    dangling: list[str]
    cycle: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "start_id": self.start_id,
            "entries": [entry.as_dict() for entry in self.entries],
            "root_id": self.root_id,
            "dangling": list(self.dangling),
            "cycle": list(self.cycle),
            "complete": not self.dangling and not self.cycle,
        }


class _CausationScope:
    """Entries written while a scope is open are threaded onto its trigger."""

    def __init__(self, trigger_id: str | None) -> None:
        self.trigger_id = trigger_id
        self.emitted: list[str] = []


# Sentinel distinguishing an explicit standalone entry (``NO_CAUSE``)
# from the default, which inherits the active causation span.
NO_CAUSE: Any = object()


class AuditLedger:
    """Append-only hash chain persisted as a JSON-lines journal."""

    journal = "audit-ledger"

    def __init__(self, store: DurableStore, clock: Clock, limit: int = 5000) -> None:
        self.store = store
        self.clock = clock
        self.limit = limit
        self._entries = [AuditEntry.from_dict(item) for item in store.read_journal(self.journal)]
        self._lock = threading.RLock()
        self._scope: ContextVar[_CausationScope | None] = ContextVar("audit-causation", default=None)
        report = self.verify()
        self._intact = bool(report["valid"])

    @staticmethod
    def _seal(body: dict[str, Any]) -> str:
        sealed = {field: body[field] for field in SEALED_FIELDS}
        return hashlib.sha256(canonical_json(sealed).encode("utf-8")).hexdigest()

    @staticmethod
    def digest(entry: dict[str, Any]) -> str:
        """Hash a persisted record exactly the way verification does."""

        return AuditLedger._seal(entry)

    # -- writing -----------------------------------------------------------

    @contextmanager
    def causation(self, trigger_id: str | None = None) -> Iterator[None]:
        """Open a causal span.

        Entries written inside the span link back to ``trigger_id`` (or, when
        omitted, to the entry most recently written by an enclosing span), so
        a sequence of audit records emitted while handling one command forms
        a single walkable causal chain.
        """

        parent = self._scope.get()
        if parent is not None:
            # A command invoked from inside another command keeps the
            # enclosing causal line (e.g. batch-complete -> batch-close,
            # shutdown -> uht-stop -> cool-stop), even when the inner
            # command names its own trigger.
            resolved = parent.emitted[-1] if parent.emitted else parent.trigger_id
        else:
            resolved = trigger_id
        scope = _CausationScope(resolved)
        token = self._scope.set(scope)
        try:
            yield
        finally:
            self._scope.reset(token)
            if parent is not None:
                # Let an enclosing command keep chaining through the entries a
                # nested command (e.g. shutdown -> stop_*) emitted.
                parent.emitted.extend(scope.emitted)

    def record(
        self,
        action: str,
        target: str,
        detail: str,
        *,
        cause: Any = None,
    ) -> AuditEntry:
        if not str(action).strip():
            raise ValidationError("audit action must not be empty")
        scope = self._scope.get()
        # ``cause=None`` (the default, and what the sections pass) means
        # "inherit the active span"; only ``NO_CAUSE`` forces a standalone row.
        if cause is None and scope is not None:
            cause = scope.emitted[-1] if scope.emitted else scope.trigger_id
        if cause is NO_CAUSE:
            cause = None
        cause = None if cause is None else str(cause)
        with self._lock:
            if not self._intact:
                raise LedgerIntegrityError(
                    "refusing to append to an audit chain that failed verification",
                    journal=self.journal,
                )
            if cause is not None and self.get(cause) is None:
                raise ValidationError("audit cause does not reference a known entry", cause=cause)
            sequence = (self._entries[-1].sequence + 1) if self._entries else 1
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
            body["entry_hash"] = self._seal(body)
            entry = AuditEntry(**body)
            self._entries.append(entry)
            if len(self._entries) > self.limit:
                # Rotate the journal ourselves rather than via the generic
                # store cap: the surviving keeps are never renumbered or
                # re-sealed, so their hashes keep proving what was written.
                self._entries = self._entries[-self.limit :]
                self.store.write_journal(self.journal, [item.as_dict() for item in self._entries])
            else:
                self.store.append_journal(self.journal, entry.as_dict())
            if scope is not None:
                scope.emitted.append(entry.entry_id)
            return entry

    # -- reading -----------------------------------------------------------

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
        label = str(entry_id)
        for entry in reversed(self._entries):
            if entry.entry_id == label:
                return entry
        return None

    def find(
        self,
        action: str,
        *,
        detail: str | None = None,
        target: str | None = None,
    ) -> AuditEntry | None:
        """Return the newest entry matching the action (and optional keys)."""

        for entry in reversed(self._entries):
            if entry.action != action:
                continue
            if detail is not None and entry.detail != detail:
                continue
            if target is not None and entry.target != target:
                continue
            return entry
        return None

    def trail(self, entry_id: str) -> list[AuditEntry]:
        """Walk ``cause`` edges back to the root, oldest first."""

        return list(self.trace(entry_id).entries)

    def trace(self, entry_id: str) -> CausalTrace:
        """Follow the causal edges and report dangling links or cycles."""

        start = self.get(entry_id)
        if start is None:
            return CausalTrace(str(entry_id), [], None, [str(entry_id)], [])
        chain: list[AuditEntry] = [start]
        seen: dict[str, int] = {start.entry_id: 0}
        dangling: list[str] = []
        cycle: list[str] = []
        current = start
        while current.cause is not None:
            parent = self.get(current.cause)
            if parent is None:
                dangling.append(current.cause)
                break
            if parent.entry_id in seen:
                cycle = [entry.entry_id for entry in chain[seen[parent.entry_id] :]] + [parent.entry_id]
                break
            chain.append(parent)
            seen[parent.entry_id] = len(chain) - 1
            current = parent
        chain.reverse()
        root_id = None if dangling or cycle else chain[0].entry_id
        return CausalTrace(str(entry_id), chain, root_id, dangling, cycle)

    def targets(self) -> dict[str, dict[str, Any]]:
        counts: dict[str, dict[str, Any]] = {}
        for entry in self._entries:
            item = counts.setdefault(entry.target, {"count": 0, "actions": {}, "latest": entry.timestamp})
            item["count"] += 1
            item["actions"][entry.action] = item["actions"].get(entry.action, 0) + 1
            item["latest"] = entry.timestamp
        return counts

    # -- verification ------------------------------------------------------

    def _failure(self, reason: str, entry: AuditEntry, **details: Any) -> dict[str, Any]:
        report: dict[str, Any] = {"valid": False, "reason": reason, "at": entry.entry_id, "sequence": entry.sequence}
        report.update(details)
        return report

    def verify(self) -> dict[str, Any]:
        """Recompute every seal and check every temporal interlock.

        The journal may have been compacted to its newest entries, so the
        first retained record is treated as the local genesis; from there the
        sequence must stay contiguous and every seal must interlock.
        """

        previous_hash = GENESIS_HASH
        expected_sequence: int | None = None
        for index, entry in enumerate(self._entries):
            is_genesis = index == 0
            if not entry.entry_hash:
                return self._failure("missing-hash", entry)
            recomputed = self._seal(entry.as_dict())
            if recomputed != entry.entry_hash:
                return self._failure(
                    "entry-hash-mismatch",
                    entry,
                    expected=recomputed,
                    actual=entry.entry_hash,
                )
            if not is_genesis:
                if entry.previous_hash != previous_hash:
                    return self._failure(
                        "chain-link-broken",
                        entry,
                        expected=previous_hash,
                        actual=entry.previous_hash,
                    )
                if entry.sequence != expected_sequence:
                    return self._failure(
                        "sequence-gap",
                        entry,
                        expected=expected_sequence,
                        actual=entry.sequence,
                    )
            expected_entry_id = f"aud-{entry.sequence:08d}"
            if entry.entry_id != expected_entry_id:
                return self._failure(
                    "entry-id-mismatch",
                    entry,
                    expected=expected_entry_id,
                    actual=entry.entry_id,
                )
            # A retained genesis may legitimately cite a cause dropped by
            # compaction; every later link must resolve inside the journal.
            if not is_genesis and entry.cause is not None and self.get(entry.cause) is None:
                return self._failure("dangling-cause", entry, missing=entry.cause)
            previous_hash = entry.entry_hash
            expected_sequence = entry.sequence + 1
        head = GENESIS_HASH if not self._entries else self._entries[-1].entry_hash
        return {"valid": True, "entries": len(self._entries), "head": head}

    def require_intact(self) -> None:
        """Re-verify and raise if the chain has been tampered with."""

        report = self.verify()
        self._intact = bool(report["valid"])
        if not self._intact:
            raise LedgerIntegrityError("audit chain verification failed", **{k: v for k, v in report.items() if k != "valid"})

    def size(self) -> int:
        return len(self._entries)

    def latest(self) -> AuditEntry | None:
        return None if not self._entries else self._entries[-1]


__all__ = ["GENESIS_HASH", "SEALED_FIELDS", "NO_CAUSE", "AuditEntry", "AuditLedger", "CausalTrace"]
