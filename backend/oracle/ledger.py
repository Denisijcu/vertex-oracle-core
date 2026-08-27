"""Ledger forense: cadena de hashes SHA-256 sobre SQLite.

Cada entrada encadena con la anterior:  hash_n = SHA256(hash_{n-1} || payload_n)
Romper o editar cualquier fila invalida toda la cadena a partir de ahi.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    mission_id: str
    kind: str
    payload: dict
    prev_hash: str
    entry_hash: str


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, ts: float, mission_id: str, kind: str, payload: dict) -> str:
    blob = f"{prev_hash}|{ts:.6f}|{mission_id}|{kind}|{_canonical(payload)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: str | Path = "oracle_ledger.db") -> None:
        self.path = str(path)
        self._con = sqlite3.connect(self.path)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute(
            """CREATE TABLE IF NOT EXISTS ledger (
                   seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts         REAL NOT NULL,
                   mission_id TEXT NOT NULL,
                   kind       TEXT NOT NULL,
                   payload    TEXT NOT NULL,
                   prev_hash  TEXT NOT NULL,
                   entry_hash TEXT NOT NULL UNIQUE
               )"""
        )
        self._con.commit()

    def head(self) -> str:
        row = self._con.execute("SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, mission_id: str, kind: str, payload: dict) -> Entry:
        prev = self.head()
        ts = time.time()
        h = compute_hash(prev, ts, mission_id, kind, payload)
        cur = self._con.execute(
            "INSERT INTO ledger (ts, mission_id, kind, payload, prev_hash, entry_hash) VALUES (?,?,?,?,?,?)",
            (ts, mission_id, kind, _canonical(payload), prev, h),
        )
        self._con.commit()
        return Entry(cur.lastrowid, ts, mission_id, kind, payload, prev, h)

    def verify(self) -> tuple[bool, int | None]:
        """Recorre la cadena. Devuelve (ok, seq_de_la_primera_fila_rota)."""
        prev = GENESIS
        for seq, ts, mid, kind, payload, prev_hash, entry_hash in self._con.execute(
            "SELECT seq, ts, mission_id, kind, payload, prev_hash, entry_hash FROM ledger ORDER BY seq"
        ):
            if prev_hash != prev:
                return False, seq
            if compute_hash(prev, ts, mid, kind, json.loads(payload)) != entry_hash:
                return False, seq
            prev = entry_hash
        return True, None

    def entries(self, mission_id: str | None = None):
        sql = "SELECT seq, ts, mission_id, kind, payload, prev_hash, entry_hash FROM ledger"
        args: tuple = ()
        if mission_id:
            sql += " WHERE mission_id = ?"
            args = (mission_id,)
        sql += " ORDER BY seq"
        for seq, ts, mid, kind, payload, prev_hash, entry_hash in self._con.execute(sql, args):
            yield Entry(seq, ts, mid, kind, json.loads(payload), prev_hash, entry_hash)

    def close(self) -> None:
        self._con.close()
