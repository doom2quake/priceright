"""Durable state / memory for agent runs.

Backed by Firestore in production, with an explicit in-memory fallback so an app
is runnable locally without credentials. A *run* is one cycle; findings, actions,
and guardrail decisions are appended to the run document so the whole causal
chain is auditable.

Core run schema (app-specific fields go under `data`):
    {
      "run_id":     str,
      "status":     str,            # app-defined lifecycle label
      "started_at": ISO-8601 str,
      "updated_at": ISO-8601 str,
      "trigger":    dict,           # what kicked off the run
      "guardrails": list[dict],     # named guardrail decisions (audit trail)
      "signature":  str | None,     # stable key for recurrence detection
      "recurrence": dict | None,    # {count, window_days, last_seen, prior_run_ids}
      "error":      str | None,
      "data":       dict,           # free-form app payload (findings, impact, ...)
    }

Two properties this module is explicit about, because both are easy to get wrong
and invisible when they are:

*Durability is never silent.* `StateStore.create` verifies Firestore with a real
bounded read before claiming it. If that read fails the store falls back to
process memory, records `degraded=True` plus the reason on the store, and, when
`AGENT_REQUIRE_DURABLE_STATE` is on, raises instead of pretending. `readiness()`
returns the machine-readable version of that for a health endpoint.

*Concurrent writers do not lose writes.* `update`, `set_data` and `append` are
read-modify-write. They run inside a Firestore transaction on the Firestore
backend and under one lock on the in-memory backend, so two threads appending a
guardrail decision and an action to the same run keep both.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import threading
import uuid
from typing import Any, Callable, Optional

from .config import BaseSettings

# mutator(doc) -> new doc (or None to leave the document untouched)
Mutator = Callable[[dict], Optional[dict]]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def new_run_id() -> str:
    return f"run-{_dt.datetime.now(_dt.timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}"


def signature_of(*parts: Any) -> str:
    """Stable short signature for recurrence detection (e.g. metric+region+direction)."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


class _InMemoryBackend:
    """Process-local dict store. Local dev / tests only.

    Deep-copies at every boundary so a caller mutating a nested list it got from
    `get()` cannot silently change stored state (Firestore, which serialises,
    would not have applied that mutation either).
    """

    durable = False

    def __init__(self) -> None:
        self._runs: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def set(self, run_id: str, doc: dict[str, Any]) -> None:
        with self._lock:
            self._runs[run_id] = copy.deepcopy(doc)

    def get(self, run_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            doc = self._runs.get(run_id)
            return copy.deepcopy(doc) if doc else None

    def mutate(self, run_id: str, mutator: Mutator) -> Optional[dict[str, Any]]:
        """Atomic read-modify-write: the whole mutation happens under one lock."""
        with self._lock:
            doc = self._runs.get(run_id)
            if doc is None:
                return None
            updated = mutator(copy.deepcopy(doc))
            if updated is None:
                return None
            self._runs[run_id] = copy.deepcopy(updated)
            return copy.deepcopy(updated)

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            docs = sorted(self._runs.values(), key=lambda d: d.get("started_at", ""), reverse=True)
            return [copy.deepcopy(d) for d in docs[:limit]]

    def find_by_signature(self, signature: str, exclude_run_id: str = "") -> list[dict[str, Any]]:
        with self._lock:
            out = [copy.deepcopy(d) for d in self._runs.values()
                   if d.get("signature") == signature and d.get("run_id") != exclude_run_id]
            return sorted(out, key=lambda d: d.get("started_at", ""), reverse=True)

    def ping(self) -> None:
        """Always available; present so both backends share one interface."""
        return None


class _FirestoreBackend:
    """Firestore-backed store. Requires google-cloud-firestore + ADC."""

    durable = True

    def __init__(self, project: str, collection: str) -> None:
        from google.cloud import firestore  # lazy import so local dev needs no dep

        self._firestore = firestore
        self._client = firestore.Client(project=project) if project else firestore.Client()
        self._collection = collection

    def _col(self):
        return self._client.collection(self._collection)

    def ping(self) -> None:
        """Bounded round trip that actually hits the service.

        Constructing a client and a CollectionReference is offline, so a missing
        API, a wrong project or a denied IAM role would otherwise only surface on
        the first real write. One `limit(1)` read forces that failure into
        `StateStore.create`, where the fallback decision is made.
        """
        list(self._col().limit(1).stream())

    def set(self, run_id: str, doc: dict[str, Any]) -> None:
        self._col().document(run_id).set(doc)

    def get(self, run_id: str) -> Optional[dict[str, Any]]:
        snap = self._col().document(run_id).get()
        return snap.to_dict() if snap.exists else None

    def mutate(self, run_id: str, mutator: Mutator) -> Optional[dict[str, Any]]:
        """Read-modify-write inside a Firestore transaction (retried on contention)."""
        ref = self._col().document(run_id)

        @self._firestore.transactional
        def _txn(transaction):
            snap = ref.get(transaction=transaction)
            if not snap.exists:
                return None
            updated = mutator(snap.to_dict() or {})
            if updated is None:
                return None
            transaction.set(ref, updated)
            return updated

        return _txn(self._client.transaction())

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        docs = self._col().order_by("started_at", direction="DESCENDING").limit(limit).stream()
        return [d.to_dict() for d in docs]

    def find_by_signature(self, signature: str, exclude_run_id: str = "") -> list[dict[str, Any]]:
        # No order_by: an equality-only query needs no composite index, so this
        # works on a fresh Firestore project. Sort in Python instead.
        try:
            from google.cloud.firestore_v1.base_query import FieldFilter

            query = self._col().where(filter=FieldFilter("signature", "==", signature))
        except Exception:  # pragma: no cover - older client without FieldFilter
            query = self._col().where("signature", "==", signature)
        docs = query.limit(50).stream()
        out = [d.to_dict() for d in docs if d.to_dict().get("run_id") != exclude_run_id]
        return sorted(out, key=lambda d: d.get("started_at", ""), reverse=True)


class StateStore:
    """High-level run API over whichever backend is available."""

    def __init__(self, backend: Any, backend_name: str, degraded: bool = False,
                 degraded_reason: str = "") -> None:
        self._backend = backend
        self.backend_name = backend_name
        #: True when durable state was wanted but could not be reached
        self.degraded = degraded
        self.degraded_reason = degraded_reason
        # Serialises read-modify-write for backends that do not implement
        # `mutate` themselves (e.g. a custom DI'd test double).
        self._fallback_lock = threading.RLock()

    @property
    def durable(self) -> bool:
        """True when writes survive process restart."""
        return bool(getattr(self._backend, "durable", False))

    def readiness(self) -> dict[str, Any]:
        """Machine-readable state health, for a `/healthz` or a demo banner."""
        return {
            "backend": self.backend_name,
            "durable": self.durable,
            "degraded": self.degraded,
            "reason": self.degraded_reason,
        }

    @classmethod
    def create(cls, settings: BaseSettings, backend_factory: Optional[Callable[[], Any]] = None) -> "StateStore":
        """Pick Firestore if it actually answers, else fall back to in-memory.

        In-memory is only silent when the app opted into it (`use_in_memory_state`).
        Any other fallback is recorded as `degraded` with the reason, and raises
        instead when `settings.require_durable_state` is set.

        `backend_factory` is a test/DI seam for supplying a backend.
        """
        if settings.use_in_memory_state:
            return cls(_InMemoryBackend(), "in-memory (explicit opt-in)")
        factory = backend_factory or (
            lambda: _FirestoreBackend(settings.project, settings.firestore_collection))
        try:
            backend = factory()
            backend.ping()  # real bounded round trip, not just client construction
            name = getattr(backend, "name", None) or f"firestore:{settings.firestore_collection}"
            return cls(backend, name)
        except Exception as exc:
            reason = f"{exc.__class__.__name__}: {exc}"
            if settings.require_durable_state:
                raise RuntimeError(
                    "durable state required (AGENT_REQUIRE_DURABLE_STATE) but the "
                    f"Firestore backend is unavailable: {reason}"
                ) from exc
            return cls(_InMemoryBackend(), "in-memory (durable state unavailable)",
                       degraded=True, degraded_reason=reason)

    # --- run lifecycle -------------------------------------------------------

    def start_run(self, trigger: Optional[dict[str, Any]] = None, status: str = "started") -> str:
        run_id = new_run_id()
        now = _now()
        self._backend.set(run_id, {
            "run_id": run_id, "status": status, "started_at": now, "updated_at": now,
            "trigger": trigger or {}, "guardrails": [], "signature": None,
            "recurrence": None, "error": None, "data": {},
        })
        return run_id

    def get(self, run_id: str) -> Optional[dict[str, Any]]:
        return self._backend.get(run_id)

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._backend.list(limit)

    def set_status(self, run_id: str, status: str, **fields: Any) -> None:
        self.update(run_id, status=status, **fields)

    # --- atomic mutations ----------------------------------------------------

    def _mutate(self, run_id: str, mutator: Mutator) -> None:
        """Apply `mutator` to the run document without losing a concurrent write."""
        backend_mutate = getattr(self._backend, "mutate", None)
        if callable(backend_mutate):
            backend_mutate(run_id, mutator)
            return
        # Backend has no atomic primitive: serialise in-process. Still not safe
        # across processes, which is why the built-in backends implement mutate.
        with self._fallback_lock:
            doc = self._backend.get(run_id)
            if doc is None:
                return
            updated = mutator(doc)
            if updated is not None:
                self._backend.set(run_id, updated)

    def update(self, run_id: str, **fields: Any) -> None:
        def _apply(doc: dict[str, Any]) -> dict[str, Any]:
            doc.update(fields)
            doc["updated_at"] = _now()
            return doc

        self._mutate(run_id, _apply)

    def set_data(self, run_id: str, key: str, value: Any) -> None:
        """Set an app-specific field under the run's `data` payload."""

        def _apply(doc: dict[str, Any]) -> dict[str, Any]:
            data = dict(doc.get("data") or {})
            data[key] = value
            doc["data"] = data
            doc["updated_at"] = _now()
            return doc

        self._mutate(run_id, _apply)

    def append(self, run_id: str, key: str, item: Any) -> None:
        """Append to a top-level list field (creates it if absent)."""

        def _apply(doc: dict[str, Any]) -> dict[str, Any]:
            lst = list(doc.get(key) or [])
            lst.append(item)
            doc[key] = lst
            doc["updated_at"] = _now()
            return doc

        self._mutate(run_id, _apply)

    def record_guardrail(self, run_id: str, name: str, outcome: str, detail: str = "") -> None:
        """Append a named guardrail decision to the run's audit trail.

        Signature matches `agent_core.sinks.Recorder` so a `Notifier` can be wired
        to a run: `Notifier(..., recorder=lambda n, o, d: store.record_guardrail(rid, n, o, d))`.
        """
        self.append(run_id, "guardrails", {"name": name, "outcome": outcome, "detail": detail, "at": _now()})

    def fail(self, run_id: str, error: str) -> None:
        self.update(run_id, status="error", error=error)

    # --- recurrence memory ---------------------------------------------------

    def detect_recurrence(self, run_id: str, signature: str, window_days: int = 7) -> Optional[dict[str, Any]]:
        """Record `signature` on the run and, if the same signature was seen within
        `window_days`, return a recurrence record (raises severity for the app)."""
        try:
            prior = self._backend.find_by_signature(signature, exclude_run_id=run_id)
        except Exception:
            # Recurrence memory is best-effort; never let it break a run.
            self.update(run_id, signature=signature, recurrence=None)
            return None
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=window_days)
        recent = []
        for d in prior:
            ts = d.get("started_at", "")
            try:
                when = _dt.datetime.fromisoformat(ts)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=_dt.timezone.utc)
            except Exception:
                continue
            if when >= cutoff:
                recent.append(d)
        recurrence = None
        if recent:
            recurrence = {
                "count": len(recent) + 1,
                "window_days": window_days,
                "last_seen": recent[0].get("started_at"),
                "prior_run_ids": [d.get("run_id") for d in recent][:10],
            }
        self.update(run_id, signature=signature, recurrence=recurrence)
        return recurrence
