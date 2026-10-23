"""SQLite event store. Ingestion is idempotent: re-ingesting a file adds nothing."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable

from .models import Event
from .parsers import parse_timestamp

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    ts          TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    src_port    INTEGER,
    event_type  TEXT NOT NULL,
    username    TEXT,
    password    TEXT,
    command     TEXT,
    url         TEXT,
    session     TEXT,
    source      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
"""

_COLUMNS = ("ts", "src_ip", "src_port", "event_type", "username", "password",
            "command", "url", "session", "source")


def _ts(event: Event) -> str:
    # Fixed-width format so lexical ordering in SQLite equals time ordering.
    return event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def _row(event: Event) -> tuple:
    return (_ts(event), event.src_ip, event.src_port, event.event_type, event.username,
            event.password, event.command, event.url, event.session, event.source)


def fingerprint(event: Event) -> str:
    raw = "\x1f".join("" if v is None else str(v) for v in _row(event))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EventStore:
    def __init__(self, path: str = "honeysiem.db"):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def add(self, events: Iterable[Event]) -> int:
        """Insert events, skipping duplicates. Returns the number of new rows."""
        before = self.conn.total_changes
        with self.conn:
            self.conn.executemany(
                f"INSERT OR IGNORE INTO events (fingerprint, {', '.join(_COLUMNS)}) "
                f"VALUES ({', '.join('?' * (len(_COLUMNS) + 1))})",
                ((fingerprint(e), *_row(e)) for e in events),
            )
        return self.conn.total_changes - before

    def events(self) -> list[Event]:
        rows = self.conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM events ORDER BY ts, id"
        ).fetchall()
        return [
            Event(timestamp=parse_timestamp(ts), src_ip=ip, src_port=port, event_type=etype,
                  username=user, password=pw, command=cmd, url=url, session=sess, source=src)
            for ts, ip, port, etype, user, pw, cmd, url, sess, src in rows
        ]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
