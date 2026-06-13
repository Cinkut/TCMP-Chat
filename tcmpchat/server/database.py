"""DatabaseLayer - warstwa dostępu do SQLite dla serwera TCMPChat.

Wszystkie metody są thread-safe: jedno połączenie współdzielone przez wątki
(``check_same_thread=False``) chronione pojedynczym ``threading.Lock``.
Schemat ładowany jest z ``db/init.sql`` (idempotentne CREATE TABLE IF NOT EXISTS).
"""

import os
import sqlite3
import threading
import time

import tcmp

_INIT_SQL = os.path.join(os.path.dirname(__file__), "..", "db", "init.sql")


class DatabaseLayer:
    def __init__(self, db_path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")

    # ----------------------------------------------------------------- schema
    def init_schema(self) -> None:
        with self._lock, open(_INIT_SQL, encoding="utf-8") as fh:
            self._conn.executescript(fh.read())
            self._conn.commit()

    def cleanup_expired_sessions(self) -> int:
        """Usuwa sesje, których token sesyjny wygasł (expires_at < now). Zwraca liczbę."""
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------ users
    def create_user(self, username: str, password_hash: str) -> bool:
        """Tworzy konto. Zwraca False gdy nazwa jest już zajęta."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user(self, username: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return dict(row) if row else None

    # --------------------------------------------------------------- messages
    def save_message(
        self, sender: str, recipient: str, type_: int, payload: bytes, timestamp: int
    ) -> int:
        """Zapisuje wiadomość z delivered=0. Zwraca message_id (lastrowid)."""
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO messages (sender, recipient, type, payload, timestamp, delivered)
                   VALUES (?, ?, ?, ?, ?, 0)""",
                (sender, recipient, type_, payload, timestamp),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_queued_messages(self, username: str) -> list[dict]:
        """Niedostarczone wiadomości dla użytkownika, posortowane chronologicznie (po id)."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, sender, recipient, type, payload, timestamp
                   FROM messages WHERE recipient = ? AND delivered = 0 ORDER BY id""",
                (username,),
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_delivered(self, message_id: int) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "UPDATE messages SET delivered = 1, delivered_at = ? WHERE id = ?",
                (now, message_id),
            )
            self._conn.commit()

    # --------------------------------------------------------------- sessions
    def create_session(self, username: str, session_token: str, session_key: bytes) -> None:
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None:
                raise ValueError(f"create_session: brak użytkownika '{username}'")
            self._conn.execute(
                """INSERT INTO sessions
                   (user_id, token, session_key, created_at, expires_at, resume_expires_at)
                   VALUES (?, ?, ?, ?, ?, NULL)""",
                (row["id"], session_token, session_key, now, now + tcmp.TOKEN_TTL),
            )
            self._conn.commit()

    def get_session_by_token(self, token: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """SELECT s.id, s.token, s.session_key, s.created_at, s.expires_at,
                          s.resume_expires_at, u.username
                   FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token = ?""",
                (token,),
            ).fetchone()
            return dict(row) if row else None

    def invalidate_session(self, session_token: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
            self._conn.commit()

    def set_resume_expiry(self, session_token: str, expires_at: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET resume_expires_at = ? WHERE token = ?",
                (expires_at, session_token),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
