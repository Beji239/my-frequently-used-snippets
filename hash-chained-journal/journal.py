import hashlib
import json
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS integrity_journal (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at    TEXT NOT NULL,
    operation      TEXT NOT NULL,
    table_name     TEXT,
    row_ref        TEXT,
    payload_digest TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
)
"""


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()


def _digest(payload) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash, recorded_at, operation, table_name, row_ref,
                payload_digest) -> str:
    parts = [prev_hash, str(recorded_at), operation, str(table_name),
             str(row_ref), payload_digest]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _head(conn) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM integrity_journal ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else GENESIS


def record(conn: sqlite3.Connection, operation: str, table_name: str = None,
           row_ref=None, payload=None) -> dict:
    recorded_at = datetime.now(timezone.utc).isoformat()
    started_here = not conn.in_transaction
    if started_here:
        conn.execute("BEGIN IMMEDIATE")
    try:
        prev = _head(conn)
        pd = _digest(payload)
        eh = _entry_hash(prev, recorded_at, operation, table_name, row_ref, pd)
        conn.execute(
            "INSERT INTO integrity_journal(recorded_at, operation, table_name,"
            " row_ref, payload_digest, prev_hash, entry_hash)"
            " VALUES (?,?,?,?,?,?,?)",
            (recorded_at, operation, table_name, str(row_ref), pd, prev, eh))
        if started_here:
            conn.commit()
    except Exception:
        if started_here:
            conn.rollback()
        raise
    return {"entry_hash": eh, "prev_hash": prev, "operation": operation}


def verify_chain(db_path: str, expected_head: str = None) -> dict:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM integrity_journal ORDER BY id ASC").fetchall()
    except sqlite3.Error as e:
        conn.close()
        return {"status": "no_journal", "detail": str(e)}
    conn.close()

    prev = GENESIS
    for r in rows:
        expect = _entry_hash(r["prev_hash"], r["recorded_at"], r["operation"],
                             r["table_name"], r["row_ref"], r["payload_digest"])
        if r["prev_hash"] != prev:
            return {"status": "broken", "first_break_id": r["id"],
                    "reason": "an entry does not follow the one before it, "
                              "so one was deleted or inserted",
                    "operation": r["operation"], "row_ref": r["row_ref"]}
        if expect != r["entry_hash"]:
            return {"status": "broken", "first_break_id": r["id"],
                    "reason": "an entry was edited after it was written",
                    "operation": r["operation"], "row_ref": r["row_ref"]}
        prev = r["entry_hash"]

    out = {"status": "intact", "verified_entries": len(rows), "head": prev}
    if expected_head and expected_head != prev:
        hit = (expected_head == GENESIS
               or any(r["entry_hash"] == expected_head for r in rows))
        if not hit:
            out["status"] = "rebuilt"
            out["reason"] = "the anchored hash is not in this chain"
    return out
