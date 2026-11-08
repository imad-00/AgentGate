# auditlog.py
import hashlib
import json
import sqlite3
import time

DB = "audit.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, tool_name TEXT, tool_input TEXT,
        allowed INTEGER, reason TEXT, prev_hash TEXT, hash TEXT
    )""")
    conn.commit()
    return conn


def _last_hash(conn) -> str:
    row = conn.execute("SELECT hash FROM log ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else "0" * 64


def append(conn, tool_name: str, tool_input: dict, allowed: bool, reason: str):
    prev = _last_hash(conn)
    ts = time.time()
    tool_input_json = json.dumps(tool_input, sort_keys=True)
    allowed_int = int(allowed)
    payload = f"{ts}|{tool_name}|{tool_input_json}|{allowed_int}|{reason}|{prev}"
    h = hashlib.sha256(payload.encode()).hexdigest()
    conn.execute(
        "INSERT INTO log (ts, tool_name, tool_input, allowed, reason, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
        (ts, tool_name, tool_input_json, allowed_int, reason, prev, h),
    )
    conn.commit()


def verify(conn) -> tuple[bool, int | None]:
    prev = "0" * 64
    rows = conn.execute(
        "SELECT id, ts, tool_name, tool_input, allowed, reason, prev_hash, hash FROM log ORDER BY id"
    )
    for id_, ts, tool_name, tool_input, allowed, reason, prev_hash, stored_hash in rows:
        if prev_hash != prev:
            return False, id_
        payload = f"{ts}|{tool_name}|{tool_input}|{allowed}|{reason}|{prev_hash}"
        if hashlib.sha256(payload.encode()).hexdigest() != stored_hash:
            return False, id_
        prev = stored_hash
    return True, None
