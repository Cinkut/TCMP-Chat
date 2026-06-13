"""Testy ClientHandler: helpery payloadu, re-stamp sendera i routing MSG.

Handler jest izolowany atrapami DB/SessionManager i gniazdami przechwytującymi
ramki; nie wymaga prawdziwej sieci ani TLS.
"""
import struct
import threading
import unittest

import tcmp
from tcmp.frame import parse_frame, pack_string
from client import protocol_messages as pm
from server.handler import ClientHandler
from server.session import MsgIdCounter


KEY = b"\x22" * 32
RKEY = b"\x33" * 32


class _FrameSock:
    """Gniazdo zapamiętujące każdą wysłaną ramkę (send_frame -> jedno sendall)."""

    def __init__(self):
        self.frames = []

    def sendall(self, data):
        self.frames.append(bytes(data))

    def settimeout(self, *_):
        pass

    def close(self):
        pass

    def shutdown(self, *_):
        pass


class _FakeDB:
    def __init__(self, users):
        self._users = set(users)
        self.saved = []
        self.delivered = []

    def get_user(self, username):
        return {"username": username} if username in self._users else None

    def save_message(self, sender, recipient, type_, payload, timestamp):
        self.saved.append({
            "sender": sender, "recipient": recipient,
            "type": type_, "payload": payload, "timestamp": timestamp,
        })
        return len(self.saved)

    def mark_delivered(self, message_id):
        self.delivered.append(message_id)


class _FakeSM:
    def __init__(self):
        self.sessions = {}

    def check_rate_limit(self, _u):
        return False

    def check_duplicate(self, _u, _mid):
        return False

    def update_activity(self, _u):
        pass

    def is_online(self, u):
        return u in self.sessions

    def get_session(self, u):
        return self.sessions.get(u)


def _make_handler(db, sm, sock=None):
    h = ClientHandler(sock or _FrameSock(), ("127.0.0.1", 1), db, None, sm)
    h.username = "alice"
    h.session_key = KEY
    return h


def _recipient_session():
    return {
        "socket": _FrameSock(),
        "send_lock": threading.Lock(),
        "msg_id_counter": MsgIdCounter(),
        "session_key": RKEY,
    }


def _file_payload(sender, recipient, filename, mimetype_id, total_filesize, data=b""):
    return (
        pack_string(sender) + pack_string(recipient)
        + struct.pack("!Q", 0)
        + pack_string(filename)
        + struct.pack("!B", mimetype_id)
        + struct.pack("!I", total_filesize)
        + data
    )


# --------------------------------------------------------------------------- #
# Statyczne helpery payloadu
# --------------------------------------------------------------------------- #
class TestStaticHelpers(unittest.TestCase):
    def test_restamp_overwrites_sender(self):
        payload = pm.encode_msg("mallory", "bob", "hej", 123)
        restamped = ClientHandler._restamp_sender(payload, "alice")
        decoded = pm.decode_msg(restamped)
        self.assertEqual(decoded["sender"], "alice")        # nadpisane
        self.assertEqual(decoded["recipient"], "bob")       # reszta nietknięta
        self.assertEqual(decoded["text"], "hej")

    def test_parse_envelope(self):
        payload = pm.encode_msg("alice", "bob", "x", 999)
        sender, recipient, ts = ClientHandler._parse_envelope(payload)
        self.assertEqual((sender, recipient, ts), ("alice", "bob", 999))

    def test_validate_file_ok(self):
        payload = _file_payload("alice", "bob", "k.png", tcmp.MIMETYPE_PNG, 10, b"0123456789")
        ClientHandler._validate_file(payload)               # nie rzuca

    def test_validate_file_bad_mimetype(self):
        payload = _file_payload("alice", "bob", "k.gif", 0x09, 5, b"x")
        with self.assertRaises(tcmp.TCMPError) as ctx:
            ClientHandler._validate_file(payload)
        self.assertEqual(ctx.exception.error_code, tcmp.ERR_MALFORMED_PAYLOAD)

    def test_validate_file_too_large(self):
        payload = _file_payload("alice", "bob", "big.png", tcmp.MIMETYPE_PNG,
                                tcmp.MAX_FILE_SIZE + 1, b"x")
        with self.assertRaises(tcmp.TCMPError) as ctx:
            ClientHandler._validate_file(payload)
        self.assertEqual(ctx.exception.error_code, tcmp.ERR_FILE_TOO_LARGE)

    def test_ack_msg_id(self):
        self.assertEqual(ClientHandler._ack_msg_id(struct.pack("!QB", 42, 0)), 42)


# --------------------------------------------------------------------------- #
# Routing MSG przez handle_data_frame
# --------------------------------------------------------------------------- #
def _msg_frame(sender, recipient, text, msg_id=7, frag_num=0, more=False):
    return {
        "type": tcmp.TYPE_MSG,
        "msg_id": msg_id,
        "frag_num": frag_num,
        "more_data": more,
        "payload": pm.encode_msg(sender, recipient, text, 123),
    }


class TestRoutingOnline(unittest.TestCase):
    def test_delivers_to_online_recipient(self):
        db = _FakeDB({"alice", "bob"})
        sm = _FakeSM()
        rsess = _recipient_session()
        sm.sessions["bob"] = rsess
        h = _make_handler(db, sm)

        h.handle_data_frame(_msg_frame("mallory", "bob", "czesc"), tcmp.TYPE_MSG)

        # Zapisana wiadomość ma autorytatywnego nadawcę (nie "mallory").
        self.assertEqual(db.saved[0]["sender"], "alice")
        self.assertEqual(db.saved[0]["recipient"], "bob")
        self.assertEqual(db.delivered, [1])                 # mark_delivered

        # Odbiorca dostał ramkę MSG z poprawnym senderem.
        fwd = pm.decode_msg(parse_frame(rsess["socket"].frames[0])["payload"])
        self.assertEqual(fwd["sender"], "alice")
        self.assertEqual(fwd["text"], "czesc")

        # Nadawca dostał ACK = delivered.
        ack = pm.decode_ack(parse_frame(h.sock.frames[0])["payload"])
        self.assertEqual(ack["status"], tcmp.ACK_STATUS_DELIVERED)


class TestRoutingOffline(unittest.TestCase):
    def test_queues_for_offline_recipient(self):
        db = _FakeDB({"alice", "bob"})
        sm = _FakeSM()                          # bob nieobecny
        h = _make_handler(db, sm)

        h.handle_data_frame(_msg_frame("alice", "bob", "czesc"), tcmp.TYPE_MSG)

        self.assertEqual(db.saved[0]["recipient"], "bob")
        self.assertEqual(db.delivered, [])                  # nie dostarczono
        ack = pm.decode_ack(parse_frame(h.sock.frames[0])["payload"])
        self.assertEqual(ack["status"], tcmp.ACK_STATUS_QUEUED)


class TestRoutingErrors(unittest.TestCase):
    def test_unknown_recipient_raises(self):
        db = _FakeDB({"alice"})                 # bob nie istnieje
        sm = _FakeSM()
        h = _make_handler(db, sm)
        with self.assertRaises(tcmp.TCMPError) as ctx:
            h.handle_data_frame(_msg_frame("alice", "bob", "x"), tcmp.TYPE_MSG)
        self.assertEqual(ctx.exception.error_code, tcmp.ERR_UNKNOWN_RECIPIENT)

    def test_rate_limit_raises(self):
        db = _FakeDB({"alice", "bob"})
        sm = _FakeSM()
        sm.check_rate_limit = lambda _u: True
        h = _make_handler(db, sm)
        with self.assertRaises(tcmp.TCMPError) as ctx:
            h.handle_data_frame(_msg_frame("alice", "bob", "x"), tcmp.TYPE_MSG)
        self.assertEqual(ctx.exception.error_code, tcmp.ERR_RATE_LIMIT)

    def test_duplicate_raises(self):
        db = _FakeDB({"alice", "bob"})
        sm = _FakeSM()
        sm.check_duplicate = lambda _u, _mid: True
        h = _make_handler(db, sm)
        with self.assertRaises(tcmp.TCMPError) as ctx:
            h.handle_data_frame(_msg_frame("alice", "bob", "x"), tcmp.TYPE_MSG)
        self.assertEqual(ctx.exception.error_code, tcmp.ERR_DUPLICATE_MSG)


class TestFragmentAck(unittest.TestCase):
    def test_intermediate_fragment_acked_not_saved(self):
        db = _FakeDB({"alice", "bob"})
        sm = _FakeSM()
        h = _make_handler(db, sm)
        # Fragment pośredni (MORE_DATA=1) - potwierdzony, ale nic nie zapisane.
        parsed = {"type": tcmp.TYPE_MSG, "msg_id": 9, "frag_num": 0,
                  "more_data": True, "payload": b"partial-bytes"}
        h.handle_data_frame(parsed, tcmp.TYPE_MSG)
        self.assertEqual(db.saved, [])
        ack = pm.decode_ack(parse_frame(h.sock.frames[0])["payload"])
        self.assertEqual(ack["status"], tcmp.ACK_STATUS_DELIVERED)


if __name__ == "__main__":
    unittest.main()
