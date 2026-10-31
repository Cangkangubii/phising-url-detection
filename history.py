import hmac
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone

DB_PATH = "history.db"
KEY_PATH = "secret.key"
GENESIS_HASH = "0" * 64


def _load_key():
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(KEY_PATH, "rb") as f:
        return f.read()


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                label       TEXT    NOT NULL,
                safe_prob   REAL    NOT NULL,
                checked_at  TEXT    NOT NULL,
                prev_hash   TEXT    NOT NULL,
                record_hash TEXT    NOT NULL
            )
            """
        )


def _compute_hash(key, prev_hash, url, label, safe_prob, checked_at):
    message = f"{prev_hash}|{url}|{label}|{safe_prob:.6f}|{checked_at}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def add_record(url, label, safe_prob):
    key = _load_key()
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect() as conn:
        row = conn.execute(
            "SELECT record_hash FROM checks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["record_hash"] if row else GENESIS_HASH
        record_hash = _compute_hash(key, prev_hash, url, label, safe_prob, checked_at)
        conn.execute(
            "INSERT INTO checks (url, label, safe_prob, checked_at, prev_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, label, safe_prob, checked_at, prev_hash, record_hash),
        )


def list_records():
    with _connect() as conn:
        return conn.execute("SELECT * FROM checks ORDER BY id DESC").fetchall()


def verify_chain():
    """Returns (ok, broken_ids). A row is broken if its hash or link to the previous row is wrong."""
    key = _load_key()
    broken = []
    expected_prev = GENESIS_HASH
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM checks ORDER BY id ASC").fetchall()
    for row in rows:
        expected_hash = _compute_hash(
            key, row["prev_hash"], row["url"], row["label"], row["safe_prob"], row["checked_at"]
        )
        if row["prev_hash"] != expected_prev or not hmac.compare_digest(
            row["record_hash"], expected_hash
        ):
            broken.append(row["id"])
        expected_prev = row["record_hash"]
    return (len(broken) == 0, broken)
