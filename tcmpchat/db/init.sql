-- TCMP Chat - schemat bazy danych SQLite
-- Uruchom: sqlite3 tcmpchat.db < init.sql

PRAGMA foreign_keys = ON;
PRAGMA journal_mode  = WAL;
PRAGMA synchronous   = NORMAL;

-- ---------------------------------------------------------------------------
-- Użytkownicy
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE
                          CHECK(length(username) BETWEEN 1 AND 64),
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ---------------------------------------------------------------------------
-- Sesje
--
-- Cykl życia pola resume_expires_at:
--   NULL              → sesja aktywna (TCP podłączone)
--   > unixepoch()     → sesja rozłączona, wznowienie możliwe
--   <= unixepoch()    → okno session-resume wygasło
--
-- expires_at = created_at + 86400  (token sesyjny ważny 24 h)
-- Token jest usuwany (DELETE) po czystym BYE lub po wygaśnięciu.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token             TEXT    NOT NULL UNIQUE,
    session_key       BLOB    NOT NULL CHECK(length(session_key) = 32),
    created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at        INTEGER NOT NULL,
    resume_expires_at INTEGER
);

-- ---------------------------------------------------------------------------
-- Wiadomości
--
-- type:    4 = MSG, 5 = FILE  (kody TYPE_* z protokołu TCMP)
-- payload: dla MSG  → surowe bajty tekstu (UTF-8)
--          dla FILE → złożone bajty pliku (po reassembly fragmentów)
-- sender/recipient przechowują login (nie id) - protokół TCMP operuje loginami.
-- delivered = 0 → wiadomość w kolejce (odbiorca był offline przy wysyłaniu)
-- delivered = 1 → dostarczona; delivered_at = czas potwierdzenia ACK
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender       TEXT    NOT NULL REFERENCES users(username),
    recipient    TEXT    NOT NULL REFERENCES users(username),
    type         INTEGER NOT NULL CHECK(type IN (4, 5)),
    payload      BLOB    NOT NULL,
    timestamp    INTEGER NOT NULL,
    delivered    INTEGER NOT NULL DEFAULT 0 CHECK(delivered IN (0, 1)),
    delivered_at INTEGER
);

-- ---------------------------------------------------------------------------
-- Indeksy
-- ---------------------------------------------------------------------------

-- Lookup tokenu przy każdej weryfikacji AUTH / session-resume
CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token);

-- Wszystkie aktywne sesje danego użytkownika (sprawdzanie czy online)
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);

-- Główne zapytanie dostarczania kolejki: recipient + delivered = 0, sorted by id
CREATE INDEX IF NOT EXISTS idx_messages_queue
    ON messages(recipient, delivered, id);

-- Historia wiadomości per nadawca (opcjonalne przyszłe funkcje)
CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages(sender);
