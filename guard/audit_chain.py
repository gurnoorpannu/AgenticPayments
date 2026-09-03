"""G6 -- hash-chained, tamper-evident audit log.

Mitigates: post-hoc repudiation and silent log editing (accountability).

Each entry commits to the SHA-256 of the entry before it. Editing any historic
entry changes its hash, which breaks every link after it, so tampering is
detectable even though it is not preventable. In VULNERABLE mode entries are
appended with no prev_hash -- an attacker who can write the log can rewrite
history undetectably, which is the point of the contrast.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from mandates.crypto import canonical_json, sha256_hex

GENESIS = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    timestamp: str
    event: str
    payload: dict[str, Any]
    prev_hash: Optional[str]
    entry_hash: Optional[str]


def compute_entry_hash(seq: int, timestamp: str, event: str, payload: dict, prev_hash: str) -> str:
    """Hash over the whole entry INCLUDING prev_hash -- this forms the chain."""
    return sha256_hex(
        {"seq": seq, "timestamp": timestamp, "event": event,
         "payload": payload, "prev_hash": prev_hash}
    )


class AuditChain:
    def __init__(self, db_path: str = ":memory:", chained: bool = True) -> None:
        """`chained=False` reproduces the vulnerable, unlinked log."""
        self.chained = chained
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                event      TEXT NOT NULL,
                payload    TEXT NOT NULL,
                prev_hash  TEXT,
                entry_hash TEXT
            )
            """
        )
        self._conn.commit()

    def append(self, event: str, payload: dict[str, Any]) -> AuditEntry:
        cur = self._conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_log")
        seq = cur.fetchone()[0] + 1
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.chained:
            row = self._conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[0] if row else GENESIS
            entry_hash = compute_entry_hash(seq, timestamp, event, payload, prev_hash)
        else:
            prev_hash = None
            entry_hash = None

        self._conn.execute(
            "INSERT INTO audit_log (seq, timestamp, event, payload, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (seq, timestamp, event, canonical_json(payload), prev_hash, entry_hash),
        )
        self._conn.commit()
        return AuditEntry(seq, timestamp, event, payload, prev_hash, entry_hash)

    def entries(self) -> list[AuditEntry]:
        import json
        rows = self._conn.execute(
            "SELECT seq, timestamp, event, payload, prev_hash, entry_hash FROM audit_log ORDER BY seq"
        ).fetchall()
        return [AuditEntry(r[0], r[1], r[2], json.loads(r[3]), r[4], r[5]) for r in rows]

    def verify_chain(self) -> tuple[bool, str]:
        """Recompute every link. Returns (intact, explanation).

        Detects: modified payloads, altered events, deleted entries, and
        entries spliced in after the fact.
        """
        rows = self.entries()
        if not self.chained:
            return False, "log is unchained (vulnerable mode): tampering is undetectable"
        if not rows:
            return True, "audit chain is empty"

        expected_prev = GENESIS
        for entry in rows:
            if entry.prev_hash != expected_prev:
                return False, (
                    f"chain broken at seq {entry.seq}: prev_hash is {str(entry.prev_hash)[:16]}... "
                    f"but the preceding entry hashes to {expected_prev[:16]}..."
                )
            recomputed = compute_entry_hash(
                entry.seq, entry.timestamp, entry.event, entry.payload, entry.prev_hash
            )
            if recomputed != entry.entry_hash:
                return False, (
                    f"entry {entry.seq} ('{entry.event}') has been modified: "
                    f"stored hash {str(entry.entry_hash)[:16]}... != recomputed {recomputed[:16]}..."
                )
            expected_prev = entry.entry_hash

        return True, f"audit chain intact across {len(rows)} entries"

    def _tamper(self, seq: int, new_payload: dict) -> None:
        """Test hook: rewrite a historic entry's payload, leaving hashes untouched."""
        self._conn.execute(
            "UPDATE audit_log SET payload = ? WHERE seq = ?", (canonical_json(new_payload), seq)
        )
        self._conn.commit()
