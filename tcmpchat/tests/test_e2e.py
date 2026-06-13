"""End-to-end: prawdziwy serwer (TLS 1.3 + własne CA) i prawdziwy klient.

Uruchamia TCMPServer w wątku na świeżej bazie SQLite, łączy się realnym
TCMPClient po TLS i sprawdza pełny przepływ: logowanie (z auto-rejestracją),
kolejkowanie wiadomości dla offline odbiorcy, dostarczenie kolejki po jego
zalogowaniu oraz routing na żywo między dwoma online klientami.

Certyfikat serwera jest podpisany własnym CA (tests/fixtures), a klient ufa
temu CA - zgodnie ze specyfikacją (self-signed bez CA jest niedopuszczalny).
Test pomijany, jeśli brak bcrypt (zależność serwera) lub plików certyfikatów.
"""
import os
import socket
import threading
import time
import unittest

try:
    import bcrypt  # noqa: F401  (wymagany przez server.auth)
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

from client.tcmp_client import TCMPClient

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")
_CA = os.path.join(_FIX, "ca_cert.pem")
_CERT = os.path.join(_FIX, "server_cert.pem")
_KEY = os.path.join(_FIX, "server_key.pem")
_HAS_CERTS = all(os.path.isfile(p) for p in (_CA, _CERT, _KEY))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("localhost", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


@unittest.skipUnless(_HAS_BCRYPT, "wymaga bcrypt (zależność serwera)")
@unittest.skipUnless(_HAS_CERTS, "wymaga certyfikatów testowych w tests/fixtures")
class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        from server.auth import AuthModule
        from server.database import DatabaseLayer
        from server.server import TCMPServer
        from server.session import SessionManager

        cls._dbfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls._dbfile.close()

        db = DatabaseLayer(cls._dbfile.name)
        db.init_schema()
        cls._db = db
        cls.port = _free_port()

        server = TCMPServer("localhost", cls.port, _CERT, _KEY,
                            db, AuthModule(db), SessionManager())
        cls._server_thread = threading.Thread(target=server.start, daemon=True)
        cls._server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._db.close()
        try:
            os.unlink(cls._dbfile.name)
        except OSError:
            pass

    def _connect(self) -> TCMPClient:
        last = None
        for _ in range(100):
            cli = TCMPClient("localhost", self.port, ping_interval=0)
            try:
                cli.connect(use_tls=True, cafile=_CA)
                return cli
            except OSError as exc:        # serwer może jeszcze nie nasłuchiwać
                last = exc
                time.sleep(0.03)
        raise AssertionError(f"nie udało się połączyć z serwerem: {last}")

    def test_queue_then_deliver_then_live(self):
        # --- bob zakłada konto i wychodzi (istnieje, ale offline) ---
        bob0 = self._connect()
        bob0.hello("E2E/bob-register")
        bob0.login("bob", "bob123")
        bob0.close()                      # clean BYE -> sesja unieważniona, bob offline
        time.sleep(0.3)                   # daj serwerowi przetworzyć BYE

        # --- alice loguje się (auto-rejestracja), bob offline ---
        alice = self._connect()
        alice.hello("E2E/alice")
        ok = alice.login("alice", "alice123")
        self.assertEqual(ok["queued_messages"], 0)
        alice_acks = []
        alice.on_ack = lambda _c, a: alice_acks.append(a)
        alice.start()

        # --- alice -> bob (offline): serwer kolejkuje, ACK = QUEUED ---
        alice.send_message("bob", "czesc bob, jestem")
        self.assertTrue(_wait_until(lambda: alice_acks), "brak ACK dla wiadomości do bob")
        self.assertEqual(alice_acks[0]["recipient"], "bob")
        self.assertEqual(alice_acks[0]["status"], 0x01)        # ACK_STATUS_QUEUED

        # --- bob loguje się: dostaje zakolejkowaną wiadomość ---
        bob = self._connect()
        bob.hello("E2E/bob")
        bob_ok = bob.login("bob", "bob123")
        self.assertGreaterEqual(bob_ok["queued_messages"], 1)
        bob_msgs = []
        bob.on_message = lambda _c, m: bob_msgs.append(m)
        bob.start()

        self.assertTrue(_wait_until(lambda: bob_msgs), "bob nie odebrał kolejki")
        self.assertEqual(bob_msgs[0]["text"], "czesc bob, jestem")

        # --- alice -> bob (teraz online): routing na żywo, ACK = DELIVERED ---
        alice_acks.clear()
        alice.send_message("bob", "teraz na zywo")
        self.assertTrue(_wait_until(lambda: alice_acks), "brak ACK dla wiadomości na żywo")
        self.assertEqual(alice_acks[0]["status"], 0x00)        # ACK_STATUS_DELIVERED
        self.assertTrue(_wait_until(lambda: len(bob_msgs) >= 2), "bob nie odebrał na żywo")
        self.assertEqual(bob_msgs[1]["text"], "teraz na zywo")

        alice.close()
        bob.close()

    def test_wrong_password_rejected(self):
        from tcmp.errors import TCMPError
        cli = self._connect()
        cli.hello("E2E/badpass")
        cli.login("alice", "alice123")   # zarejestruj/zaloguj poprawnie raz
        cli.close()

        cli2 = self._connect()
        cli2.hello("E2E/badpass2")
        with self.assertRaises(TCMPError) as ctx:
            cli2.login("alice", "zle-haslo")
        self.assertEqual(ctx.exception.error_code, 0x0009)     # ERR_AUTH_FAILED
        cli2.close(send_bye=False)


if __name__ == "__main__":
    unittest.main()
