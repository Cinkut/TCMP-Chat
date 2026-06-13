"""Testy AuthModule: rejestracja, logowanie i session resume.

Pomijane, jeśli brak bcrypt (zależność serwera).
"""
import os
import tempfile
import time
import unittest

try:
    import bcrypt  # noqa: F401
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

import tcmp
from server.database import DatabaseLayer


@unittest.skipUnless(_HAS_BCRYPT, "wymaga bcrypt (zależność serwera)")
class _AuthTestCase(unittest.TestCase):
    def setUp(self):
        from server.auth import AuthModule
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db = DatabaseLayer(self._tmp.name)
        self.db.init_schema()
        self.auth = AuthModule(self.db)

    def tearDown(self):
        self.db.close()
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass


class TestRegister(_AuthTestCase):
    def test_register_creates_user_and_session(self):
        token, key = self.auth.register("alice", "secret")
        self.assertEqual(len(key), tcmp.SESSION_KEY_LENGTH)
        self.assertIsNotNone(self.db.get_user("alice"))
        self.assertIsNotNone(self.db.get_session_by_token(token))

    def test_register_existing_username_fails(self):
        from server.auth import AuthFailedError
        self.auth.register("alice", "secret")
        with self.assertRaises(AuthFailedError):
            self.auth.register("alice", "inne")

    def test_password_not_stored_plaintext(self):
        self.auth.register("alice", "secret")
        self.assertNotIn("secret", self.db.get_user("alice")["password_hash"])


class TestLogin(_AuthTestCase):
    def setUp(self):
        super().setUp()
        self.auth.register("alice", "secret")

    def test_login_correct_password(self):
        token, key = self.auth.login("alice", "secret")
        self.assertEqual(len(key), tcmp.SESSION_KEY_LENGTH)
        self.assertIsNotNone(self.db.get_session_by_token(token))

    def test_login_wrong_password_fails(self):
        from server.auth import AuthFailedError
        with self.assertRaises(AuthFailedError):
            self.auth.login("alice", "zle")

    def test_login_missing_user_same_error(self):
        # Brak konta i złe hasło dają TEN SAM wyjątek - anti-enumeration.
        from server.auth import AuthFailedError
        with self.assertRaises(AuthFailedError):
            self.auth.login("nikt", "cokolwiek")


class TestResume(_AuthTestCase):
    def setUp(self):
        super().setUp()
        self.token, self.key = self.auth.register("alice", "secret")

    def _make_resumable(self, token, seconds_ahead=300):
        self.db.set_resume_expiry(token, int(time.time()) + seconds_ahead)

    def test_resume_valid_rotates_token(self):
        self._make_resumable(self.token)
        new_token, new_key = self.auth.resume("alice", self.token)
        self.assertNotEqual(new_token, self.token)          # rotacja tokenu
        self.assertNotEqual(new_key, self.key)              # nowy klucz HMAC
        self.assertIsNone(self.db.get_session_by_token(self.token))   # stary unieważniony
        self.assertIsNotNone(self.db.get_session_by_token(new_token))

    def test_resume_expired_fails(self):
        from server.auth import AuthFailedError
        self.db.set_resume_expiry(self.token, int(time.time()) - 1)   # okno minęło
        with self.assertRaises(AuthFailedError):
            self.auth.resume("alice", self.token)

    def test_resume_active_session_fails(self):
        # resume_expires_at == NULL (sesja nigdy nie rozłączona) -> brak wznowienia.
        from server.auth import AuthFailedError
        with self.assertRaises(AuthFailedError):
            self.auth.resume("alice", self.token)

    def test_resume_wrong_owner_fails(self):
        from server.auth import AuthFailedError
        self.auth.register("bob", "h")
        self._make_resumable(self.token)
        with self.assertRaises(AuthFailedError):
            self.auth.resume("bob", self.token)             # token nie należy do bob

    def test_resume_unknown_token_fails(self):
        from server.auth import AuthFailedError
        with self.assertRaises(AuthFailedError):
            self.auth.resume("alice", "nieistniejacy-token")


if __name__ == "__main__":
    unittest.main()
