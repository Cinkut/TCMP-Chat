"""AuthModule - rejestracja, logowanie i session resume.

Hasła hashowane bcryptem (losowy salt per użytkownik). Tokeny sesyjne i klucze
HMAC generowane kryptograficznie losowo (``secrets``). Sesje zapisywane są
w bazie przez DatabaseLayer; stan żywych połączeń trzyma SessionManager.
"""

import secrets
import time

import bcrypt

import tcmp
from server.database import DatabaseLayer


class AuthFailedError(Exception):
    """Niepowodzenie uwierzytelnienia - mapowane na ERR_AUTH_FAILED (0x0009)."""


class AuthModule:
    def __init__(self, db: DatabaseLayer):
        self.db = db

    # --------------------------------------------------------------- helpers
    def _issue_session(self, username: str) -> tuple[str, bytes]:
        token = secrets.token_hex(32)
        key = secrets.token_bytes(tcmp.SESSION_KEY_LENGTH)
        self.db.create_session(username, token, key)
        return token, key

    # ------------------------------------------------------------- operations
    def register(self, username: str, password: str) -> tuple[str, bytes]:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        if not self.db.create_user(username, password_hash):
            raise AuthFailedError("Username already taken")
        return self._issue_session(username)

    def login(self, username: str, password: str) -> tuple[str, bytes]:
        user = self.db.get_user(username)
        # Celowo identyczny komunikat dla "zły login" i "złe hasło"
        # - ochrona przed enumeracją użytkowników.
        if user is None or not bcrypt.checkpw(
            password.encode(), user["password_hash"].encode()
        ):
            raise AuthFailedError("Invalid credentials")
        return self._issue_session(username)

    def resume(self, username: str, resume_token: str) -> tuple[str, bytes]:
        session = self.db.get_session_by_token(resume_token)
        now = time.time()
        if (
            session is None
            or session["username"] != username
            or session["resume_expires_at"] is None
            or session["resume_expires_at"] < now
            or session["expires_at"] < now
        ):
            raise AuthFailedError("Invalid resume token")
        # Rotacja: nowy token i nowy klucz HMAC, stary token unieważniony.
        token, key = self._issue_session(username)
        self.db.invalidate_session(resume_token)
        return token, key

    def logout(self, session_token: str) -> None:
        self.db.invalidate_session(session_token)
