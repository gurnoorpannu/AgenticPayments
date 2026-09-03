"""G2 -- single-use nonce enforcement.

Mitigates: Attack 2, mandate replay.
Threat family F4 (State-Binding Failures), threat T-31.

A signature is not a transaction. Without single-use tracking, a captured
closed mandate stays valid forever: the signature still verifies and the
constraints are still satisfied, so a replayed mandate authorises a second
charge against one user authorisation.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from mandates.schemas import parse_iso


class NonceStore:
    """Persistent consumed-nonce set backed by SQLite.

    The UNIQUE constraint on `nonce` is what actually enforces single use --
    consumption is an atomic INSERT, not a read-then-write, so two concurrent
    replays cannot both win.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce       TEXT PRIMARY KEY,
                mandate_jti TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def consume(self, nonce: str, mandate_jti: str) -> bool:
        """Atomically claim `nonce`. Returns False if it was already used.

        Mitigates T-31 (replay of a validly signed mandate).
        """
        try:
            self._conn.execute(
                "INSERT INTO consumed_nonces (nonce, mandate_jti, consumed_at) VALUES (?, ?, ?)",
                (nonce, mandate_jti, datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def seen(self, nonce: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM consumed_nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        return row is not None

    @staticmethod
    def is_expired(expires_at: Optional[str]) -> bool:
        """Enforce mandate expiry. Absent expiry is treated as expired (fail closed)."""
        if not expires_at:
            return True
        return parse_iso(expires_at) <= datetime.now(timezone.utc)

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0]

    def reset(self) -> None:
        self._conn.execute("DELETE FROM consumed_nonces")
        self._conn.commit()
