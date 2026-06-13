"""Testy warstwy bazy danych (DatabaseLayer) na tymczasowej bazie SQLite."""
import os
import tempfile
import time
import unittest

import tcmp
from server.database import DatabaseLayer


class _DBTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db = DatabaseLayer(self._tmp.name)
        self.db.init_schema()

    def tearDown(self):
        self.db.close()
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass


class TestUsers(_DBTestCase):
    def test_create_and_get(self):
        self.assertTrue(self.db.create_user("alice", "hash-a"))
        user = self.db.get_user("alice")
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["password_hash"], "hash-a")

    def test_duplicate_username_rejected(self):
        self.assertTrue(self.db.create_user("alice", "h1"))
        self.assertFalse(self.db.create_user("alice", "h2"))   # zajęta nazwa
        self.assertEqual(self.db.get_user("alice")["password_hash"], "h1")  # bez nadpisania

    def test_get_missing_user_is_none(self):
        self.assertIsNone(self.db.get_user("nikt"))


class TestMessages(_DBTestCase):
    def setUp(self):
        super().setUp()
        self.db.create_user("alice", "h")
        self.db.create_user("bob", "h")

    def test_save_returns_id_and_queues(self):
        mid = self.db.save_message("alice", "bob", tcmp.TYPE_MSG, b"czesc", 111)
        self.assertIsInstance(mid, int)
        queue = self.db.get_queued_messages("bob")
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["payload"], b"czesc")
        self.assertEqual(queue[0]["sender"], "alice")

    def test_queue_ordered_by_id_and_filtered(self):
        m1 = self.db.save_message("alice", "bob", tcmp.TYPE_MSG, b"1", 1)
        self.db.save_message("alice", "bob", tcmp.TYPE_MSG, b"2", 2)
        self.db.mark_delivered(m1)                       # m1 znika z kolejki
        queue = self.db.get_queued_messages("bob")
        self.assertEqual([m["payload"] for m in queue], [b"2"])

    def test_mark_delivered_sets_flag_and_timestamp(self):
        mid = self.db.save_message("alice", "bob", tcmp.TYPE_MSG, b"x", 1)
        self.db.mark_delivered(mid)
        row = self.db._conn.execute(
            "SELECT delivered, delivered_at FROM messages WHERE id=?", (mid,)
        ).fetchone()
        self.assertEqual(row["delivered"], 1)
        self.assertIsNotNone(row["delivered_at"])

    def test_unknown_recipient_rejected_by_fk(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.save_message("alice", "ghost", tcmp.TYPE_MSG, b"x", 1)


class TestSessions(_DBTestCase):
    def setUp(self):
        super().setUp()
        self.db.create_user("alice", "h")

    def test_create_and_lookup(self):
        self.db.create_session("alice", "tok-1", b"\x01" * 32)
        s = self.db.get_session_by_token("tok-1")
        self.assertEqual(s["username"], "alice")
        self.assertEqual(s["session_key"], b"\x01" * 32)
        self.assertIsNone(s["resume_expires_at"])          # sesja aktywna

    def test_set_resume_expiry(self):
        self.db.create_session("alice", "tok-1", b"\x02" * 32)
        future = int(time.time()) + 300
        self.db.set_resume_expiry("tok-1", future)
        self.assertEqual(self.db.get_session_by_token("tok-1")["resume_expires_at"], future)

    def test_invalidate_deletes(self):
        self.db.create_session("alice", "tok-1", b"\x03" * 32)
        self.db.invalidate_session("tok-1")
        self.assertIsNone(self.db.get_session_by_token("tok-1"))

    def test_cleanup_expired_sessions(self):
        self.db.create_session("alice", "live", b"\x04" * 32)
        self.db.create_session("alice", "dead", b"\x05" * 32)
        # Cofnij expires_at sesji "dead" w przeszłość.
        self.db._conn.execute(
            "UPDATE sessions SET expires_at=? WHERE token='dead'",
            (int(time.time()) - 10,),
        )
        self.db._conn.commit()
        removed = self.db.cleanup_expired_sessions()
        self.assertEqual(removed, 1)
        self.assertIsNone(self.db.get_session_by_token("dead"))
        self.assertIsNotNone(self.db.get_session_by_token("live"))


if __name__ == "__main__":
    unittest.main()
