"""Testy SessionManager: rejestr sesji, duplikaty, rate limit, watchdog."""
import threading
import time
import unittest

import tcmp
from server.session import MsgIdCounter, SessionManager


class _FakeSock:
    def __init__(self):
        self.sent = bytearray()
        self.shutdown_called = False

    def sendall(self, data):
        self.sent.extend(data)

    def shutdown(self, how):
        self.shutdown_called = True


def _register(sm, username="alice", sock=None):
    sock = sock or _FakeSock()
    sm.register_session(
        username, "tok", b"\x11" * 32, sock,
        threading.Lock(), MsgIdCounter(), addr=("127.0.0.1", 5000),
    )
    return sock


class TestMsgIdCounter(unittest.TestCase):
    def test_starts_at_one_and_increments(self):
        c = MsgIdCounter()
        self.assertEqual(c.next(), 1)
        self.assertEqual(c.next(), 2)

    def test_thread_safe_unique(self):
        c = MsgIdCounter()
        seen = []
        lock = threading.Lock()

        def worker():
            for _ in range(100):
                v = c.next()
                with lock:
                    seen.append(v)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(seen), len(set(seen)))          # bez duplikatów
        self.assertEqual(max(seen), 800)


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.sm = SessionManager()

    def test_register_and_online(self):
        _register(self.sm, "alice")
        self.assertTrue(self.sm.is_online("alice"))
        self.assertIsNotNone(self.sm.get_session("alice"))

    def test_unregister(self):
        _register(self.sm, "alice")
        self.sm.unregister_session("alice")
        self.assertFalse(self.sm.is_online("alice"))
        self.assertIsNone(self.sm.get_session("alice"))

    def test_get_socket(self):
        sock = _register(self.sm, "alice")
        self.assertIs(self.sm.get_socket("alice"), sock)


class TestDuplicate(unittest.TestCase):
    def setUp(self):
        self.sm = SessionManager()
        _register(self.sm, "alice")

    def test_first_seen_then_duplicate(self):
        self.assertFalse(self.sm.check_duplicate("alice", 5))   # pierwszy raz
        self.assertTrue(self.sm.check_duplicate("alice", 5))    # powtórka

    def test_distinct_ids_not_duplicate(self):
        self.assertFalse(self.sm.check_duplicate("alice", 1))
        self.assertFalse(self.sm.check_duplicate("alice", 2))

    def test_unknown_user_not_duplicate(self):
        self.assertFalse(self.sm.check_duplicate("nikt", 1))


class TestRateLimit(unittest.TestCase):
    def setUp(self):
        self.sm = SessionManager()
        _register(self.sm, "alice")

    def test_allows_up_to_limit_then_blocks(self):
        for _ in range(tcmp.RATE_LIMIT_FRAMES):
            self.assertFalse(self.sm.check_rate_limit("alice"))
        self.assertTrue(self.sm.check_rate_limit("alice"))      # 21. ramka

    def test_window_eviction(self):
        # Wstrzyknij znaczniki starsze niż okno -> powinny zostać usunięte.
        dq = self.sm.get_session("alice")["rate_limit"]
        old = time.monotonic() - tcmp.RATE_LIMIT_WINDOW - 5
        for _ in range(tcmp.RATE_LIMIT_FRAMES):
            dq.append(old)
        self.assertFalse(self.sm.check_rate_limit("alice"))     # stare wyparte
        self.assertLessEqual(len(dq), 1)


class TestWatchdog(unittest.TestCase):
    def test_reap_idle_closes_stale_session(self):
        sm = SessionManager()
        sock = _register(sm, "alice")
        # Postarz aktywność, by sesja wpadła w timeout.
        sm._sessions["alice"]["last_activity"] = time.monotonic() - 100
        reaped = sm.reap_idle(timeout=60)
        self.assertEqual(reaped, ["alice"])
        self.assertTrue(sock.shutdown_called)                   # gniazdo zamknięte
        self.assertTrue(sock.sent)                              # wysłano BYE

    def test_active_session_not_reaped(self):
        sm = SessionManager()
        _register(sm, "alice")
        self.assertEqual(sm.reap_idle(timeout=60), [])


if __name__ == "__main__":
    unittest.main()
