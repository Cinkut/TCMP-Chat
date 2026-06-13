#!/usr/bin/env python3
"""
Inicjalizacja i seeding bazy danych TCMPChat.

Użycie:
    python seeding.py                      # tworzy tcmpchat.db w bieżącym katalogu
    python seeding.py --db /tmp/test.db    # podana ścieżka
    python seeding.py --reset              # usuwa istniejące dane przed seedingiem

Wymaga: bcrypt  (pip install bcrypt)
"""

import argparse
import sqlite3
import struct
import sys
import time
from pathlib import Path

try:
    import bcrypt
except ImportError:
    sys.exit(
        "[ERR] Brak biblioteki bcrypt. Zainstaluj: pip install bcrypt"
    )

_HERE = Path(__file__).parent
_SCHEMA = _HERE / "init.sql"
_DEFAULT_DB = Path.cwd() / "tcmpchat.db"

# ---------------------------------------------------------------------------
# Użytkownicy testowi  (login, hasło)
# ---------------------------------------------------------------------------
_USERS: list[tuple[str, str]] = [
    ("alice",  "alice123"),
    ("bob",    "bob123"),
    ("carol",  "carol123"),
]

# ---------------------------------------------------------------------------
# Wiadomości testowe  (nadawca, odbiorca, treść)
# Wszystkie mają delivered=0 — symulują kolejkę dla offline odbiorcy.
# ---------------------------------------------------------------------------
_MESSAGES: list[tuple[str, str, str]] = [
    ("bob",   "alice", "Hej alice, odezwij się jak będziesz online!"),
    ("carol", "alice", "Alice, masz czas na rozmowę?"),
    ("alice", "bob",   "Bob, wysyłam plik zaraz po zalogowaniu."),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _pack_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("!H", len(b)) + b


def _msg_payload(recipient: str, text: str, ts_ms: int) -> bytes:
    """Buduje binarny payload ramki MSG zgodny ze specyfikacją TCMP."""
    return (
        _pack_string(recipient)
        + struct.pack("!Q", ts_ms)
        + _pack_string(text)
    )


# ---------------------------------------------------------------------------
# Inicjalizacja schematu
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection) -> None:
    schema = _SCHEMA.read_text(encoding="utf-8")
    conn.executescript(schema)
    print(f"[OK] Schema załadowana z {_SCHEMA}")


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------

def seed_users(conn: sqlite3.Connection) -> dict[str, int]:
    """Wstawia użytkowników testowych. Zwraca mapę login -> id."""
    user_ids: dict[str, int] = {}
    for username, password in _USERS:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            user_ids[username] = existing[0]
            print(f"[SKIP] Użytkownik '{username}' już istnieje (id={existing[0]})")
            continue
        pw_hash = _hash_password(password)
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        user_ids[username] = cur.lastrowid
        print(f"[OK]   Dodano użytkownika '{username}' (id={cur.lastrowid})")
    return user_ids


def seed_messages(conn: sqlite3.Connection) -> None:
    now_ms = int(time.time() * 1000)
    for i, (sender, recipient, text) in enumerate(_MESSAGES):
        ts_ms = now_ms - (len(_MESSAGES) - i) * 60_000  # każda o minutę wcześniej
        payload = _msg_payload(recipient, text, ts_ms)
        conn.execute(
            """
            INSERT INTO messages (sender, recipient, type, payload, timestamp, delivered)
            VALUES (?, ?, 4, ?, ?, 0)
            """,
            (sender, recipient, payload, ts_ms),
        )
        print(f"[OK]   Wiadomość zakolejkowana: {sender} -> {recipient}: '{text[:40]}…'")


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def reset_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DELETE FROM messages;
        DELETE FROM sessions;
        DELETE FROM users;
        DELETE FROM sqlite_sequence;
        """
    )
    print("[RESET] Dane usunięte.")


# ---------------------------------------------------------------------------
# Główna logika
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="TCMPChat DB seeding")
    parser.add_argument(
        "--db",
        default=str(_DEFAULT_DB),
        metavar="ŚCIEŻKA",
        help=f"Ścieżka do pliku SQLite (domyślnie: {_DEFAULT_DB})",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wyczyść istniejące dane przed seedingiem",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Baza danych: {db_path.resolve()}")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        init_db(conn)
        if args.reset:
            reset_db(conn)
        seed_users(conn)
        seed_messages(conn)
        conn.commit()
        print("\n[GOTOWE] Baza danych zainicjalizowana i wypełniona danymi testowymi.")
        print("\nKonta testowe:")
        for username, password in _USERS:
            print(f"  {username:<10} hasło: {password}")
    except Exception as exc:
        conn.rollback()
        print(f"\n[ERR] {exc}", file=sys.stderr)
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
