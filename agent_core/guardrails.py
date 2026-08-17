"""Guardrails: an explicit, named safety layer for an agent that takes actions.

Agent actions are only safe when they are bounded. agent-core enforces guardrails
at three named points so they show up in a run's audit trail:

  1. READ_ONLY_SQL  - diagnostic queries must be a single, byte-capped,
                      comment-free SELECT/WITH statement with no export,
                      remote-fetch, locking or admin function calls
                      (see `assert_read_only`).
  2. CONTENT_SAFETY - model output is screened for prompt-injection / unsafe
                      directives before the agent acts on it (`screen_content`).
  3. ACTION_LIMITER - outbound actions (alerts, tickets, remediations) are rate-
                      capped and can be forced into dry-run, so a scheduled loop
                      cannot run away and spam humans or apply an unwanted
                      change (`ActionLimiter`).

Honest scope. `assert_read_only` is a deny-list screen over the raw statement
text, not a dialect-aware SQL parser. It is defence in depth and it is the last
line, not the only one: run generated SQL under a credential that has SELECT
only, on an allow-listed dataset, with a server-side byte/cost cap. What this
module gives you is a cheap, auditable, fail-closed pre-check and a recorded
decision. Nothing here touches the network.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass

# --- 1) read-only SQL screen -------------------------------------------------

# Default cap on the statement size we are willing to hand to a database.
DEFAULT_MAX_SQL_BYTES = 8000

# Reject anything that is not a single read-only statement. Apps that don't use
# SQL can ignore this; those that do call it before running generated SQL.
_WRITE_TOKENS = re.compile(
    r"\b(insert|update|delete|merge|drop|create|alter|truncate|grant|revoke|"
    r"replace|call|execute|exec|begin|commit|rollback|set|vacuum|analyze|copy|"
    r"load|attach|pragma|into)\b",
    re.IGNORECASE,
)

# Side-effecting / data-exfiltrating things that are still legal inside a SELECT.
# Each entry is (label, pattern). Ordered most-specific first for clear messages.
_UNSAFE_CONSTRUCTS: list[tuple[str, re.Pattern[str]]] = [
    ("file export", re.compile(r"\b(outfile|dumpfile)\b", re.IGNORECASE)),
    ("session/admin function", re.compile(
        r"\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|"
        r"pg_switch_wal|pg_create_restore_point|pg_advisory_lock|"
        r"pg_advisory_xact_lock|sp_executesql|xp_cmdshell|xp_dirtree|"
        r"kill_query|sys_exec|sys_eval)\b", re.IGNORECASE)),
    ("filesystem function", re.compile(
        r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|"
        r"lo_export|load_file|readfile|writefile|file_get_contents)\b", re.IGNORECASE)),
    ("remote/federated fetch", re.compile(
        r"\b(dblink|dblink_exec|postgres_fdw|external_query|openrowset|opendatasource|"
        r"http_get|http_post|urlread|url_fetch|net\.http_get)\b", re.IGNORECASE)),
    ("time-consuming sleep", re.compile(
        r"\b(pg_sleep|pg_sleep_for|sleep|benchmark|waitfor)\s*\(", re.IGNORECASE)),
    ("row lock", re.compile(r"\bfor\s+(update|share|no\s+key\s+update|key\s+share)\b",
                            re.IGNORECASE)),
]

# MySQL executes /*! ... */ "versioned" comments. Anything hidden in one is a
# bypass of the token screen, so its presence is an outright rejection.
_VERSIONED_COMMENT = re.compile(r"/\*!")
_LINE_COMMENT = re.compile(r"(--|#)[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def max_sql_bytes() -> int:
    """Byte cap applied by `assert_read_only` (`AGENT_MAX_SQL_BYTES`)."""
    raw = os.getenv("AGENT_MAX_SQL_BYTES", "")
    if raw.strip():
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return DEFAULT_MAX_SQL_BYTES


def _strip_comments(sql: str) -> str:
    """Remove SQL comments so they cannot hide a rejected token."""
    return _LINE_COMMENT.sub(" ", _BLOCK_COMMENT.sub(" ", sql))


def assert_read_only(sql: str, max_bytes: int | None = None) -> str | None:
    """Return an error string if `sql` is not a single safe read-only statement.

    Returns None when the statement passes every check:
      * non-empty and within the byte cap (`AGENT_MAX_SQL_BYTES`, default 8000);
      * no MySQL versioned `/*! ... */` comment (it executes);
      * exactly one statement (no `;` outside the trailing one);
      * starts with SELECT or WITH;
      * contains no write/DDL/transaction/`INTO` token, with comments stripped
        first so they cannot be used to smuggle one past the screen;
      * contains no export, filesystem, remote-fetch, admin, sleep or row-lock
        construct that a SELECT could otherwise legally carry.

    This is a text screen, not a parser. Pair it with a read-only credential.
    """
    if not sql or not sql.strip():
        return "empty query"

    cap = max_bytes if max_bytes is not None else max_sql_bytes()
    size = len(sql.encode("utf-8"))
    if size > cap:
        return f"query too large: {size} bytes exceeds the {cap}-byte cap"

    if _VERSIONED_COMMENT.search(sql):
        return "MySQL versioned comment (/*! ... */) is executable and not allowed"

    # Analyse the comment-free text: `select 1 -- ; drop table t` must not pass
    # by hiding a rejected token behind a comment marker.
    cleaned = _strip_comments(sql).strip().rstrip(";").strip()
    if not cleaned:
        return "query contains no statement outside comments"
    if ";" in cleaned:
        return "multiple statements are not allowed (single SELECT/WITH only)"

    low = cleaned.lstrip("(").lstrip().lower()
    if not (low.startswith("select") or low.startswith("with")):
        return "only SELECT/WITH queries are allowed"

    hit = _WRITE_TOKENS.search(cleaned)
    if hit:
        return f"write/DDL keyword not allowed: {hit.group(0)!r}"

    for label, pattern in _UNSAFE_CONSTRUCTS:
        found = pattern.search(cleaned)
        if found:
            return f"{label} not allowed: {found.group(0).strip()!r}"
    return None


# --- 2) content-safety screen ------------------------------------------------

# Phrases that, in *model-generated* text we're about to act on, suggest prompt-
# injection or an attempt to escalate beyond the agent's remit.
_INJECTION_PATTERNS = re.compile(
    r"(ignore (all |previous )?instructions|disregard .{0,20}(rules|guardrails)|"
    r"you are now|system prompt|exfiltrate|delete .{0,20}(table|dataset|database)|"
    r"drop table|reveal .{0,20}(secret|token|credential|api key))",
    re.IGNORECASE,
)


def screen_content(text: str) -> tuple[bool, str]:
    """Return (is_safe, reason). Screens model output before the agent acts on it."""
    if not text:
        return True, "empty"
    hit = _INJECTION_PATTERNS.search(text)
    if hit:
        return False, f"blocked pattern: {hit.group(0)!r}"
    return True, "clean"


# --- 3) action rate / spend limiter ------------------------------------------

@dataclass
class ActionPolicy:
    """Bounds on an agent's outbound actions."""

    dry_run: bool
    max_actions_per_cycle: int
    max_actions_per_hour: int

    @classmethod
    def from_env(cls, prefix: str = "AGENT") -> "ActionPolicy":
        """Read `{prefix}_DRY_RUN`, `{prefix}_MAX_ACTIONS_PER_CYCLE`,
        `{prefix}_MAX_ACTIONS_PER_HOUR` with safe defaults."""

        def _b(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}

        return cls(
            dry_run=_b(f"{prefix}_DRY_RUN", False),
            max_actions_per_cycle=int(os.getenv(f"{prefix}_MAX_ACTIONS_PER_CYCLE", "4")),
            max_actions_per_hour=int(os.getenv(f"{prefix}_MAX_ACTIONS_PER_HOUR", "20")),
        )


class ActionLimiter:
    """Process-wide, thread-safe rate limiter for outbound actions.

    A long-running deployment shares one limiter, so a runaway loop is throttled
    across cycles, not just within one.

    Per-cycle counters are keyed by run id. Callers are not required to call
    `reset_cycle`: entries older than the hourly window are evicted on every
    check, and the table is hard-capped, so a long-lived process that mints a new
    run id per cycle does not grow without bound.
    """

    #: per-cycle counters older than this (seconds) are dropped on the next check
    CYCLE_TTL_SECONDS = 3600
    #: hard ceiling on tracked run ids; the oldest are evicted past this
    MAX_TRACKED_CYCLES = 1024

    def __init__(self, policy: ActionPolicy | None = None) -> None:
        self.policy = policy or ActionPolicy.from_env()
        self._lock = threading.Lock()
        self._recent: list[float] = []  # unix timestamps of allowed actions
        # run_id -> (count, last_used_epoch)
        self._cycle_counts: dict[str, tuple[int, float]] = {}

    def _evict(self, now: float) -> None:
        """Drop expired per-cycle counters. Caller holds the lock."""
        expired = [rid for rid, (_, seen) in self._cycle_counts.items()
                   if now - seen > self.CYCLE_TTL_SECONDS]
        for rid in expired:
            self._cycle_counts.pop(rid, None)
        overflow = len(self._cycle_counts) - self.MAX_TRACKED_CYCLES
        if overflow > 0:
            oldest = sorted(self._cycle_counts.items(), key=lambda kv: kv[1][1])[:overflow]
            for rid, _ in oldest:
                self._cycle_counts.pop(rid, None)

    def check(self, run_id: str, kind: str) -> tuple[bool, str]:
        """Return (allowed, reason). `kind` is e.g. 'alert', 'ticket', 'remediate'."""
        if self.policy.dry_run:
            return False, f"dry-run enabled; {kind} suppressed"
        now = time.time()
        with self._lock:
            self._recent = [t for t in self._recent if now - t < 3600]
            self._evict(now)
            if len(self._recent) >= self.policy.max_actions_per_hour:
                return False, f"hourly action cap reached ({self.policy.max_actions_per_hour}/h)"
            used, _ = self._cycle_counts.get(run_id, (0, now))
            if used >= self.policy.max_actions_per_cycle:
                return False, f"per-cycle action cap reached ({self.policy.max_actions_per_cycle}/cycle)"
            self._recent.append(now)
            self._cycle_counts[run_id] = (used + 1, now)
            return True, f"allowed ({used + 1}/{self.policy.max_actions_per_cycle} this cycle)"

    def tracked_cycles(self) -> int:
        """Number of run ids currently holding a per-cycle counter."""
        with self._lock:
            return len(self._cycle_counts)

    def reset_cycle(self, run_id: str) -> None:
        """Clear the per-cycle counter for a run (call at the start of a new cycle)."""
        with self._lock:
            self._cycle_counts.pop(run_id, None)
