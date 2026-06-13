"""Test integracyjny klienta przez socketpair (mini-serwer w wątku).

Weryfikuje pełny przepływ MVP na poziomie bajtów bez prawdziwego serwera:
HELLO -> AUTH -> AUTH_OK -> odbiór MSG (auto-ACK) -> wysłanie MSG.
"""
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

from tcmp import constants as c
from tcmp.frame import build_frame, parse_frame, recv_frame, send_frame, pack_string
from tcmp.fragment import ReassemblyBuffer, fragment_payload
from client import protocol_messages as pm
from client.tcmp_client import TCMPClient


KEY = b"\x5A" * c.SESSION_KEY_LENGTH


def _encode_auth_ok(token: str, key: bytes, queued: int) -> bytes:
    return pack_string(token) + struct.pack("!H", len(key)) + key + struct.pack("!I", queued)


def _wait_until(pred, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.005)
    return False


class TestClientFullFlow(unittest.TestCase):
    def test_handshake_recv_ack_and_send(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)
        results = {}

        def fake_server():
            try:
                hello = parse_frame(recv_frame(s_end))
                results["hello_type"] = hello["type"]

                auth = parse_frame(recv_frame(s_end))
                results["auth_type"] = auth["type"]

                send_frame(s_end, build_frame(
                    c.TYPE_AUTH_OK, 0, 1, 0,
                    _encode_auth_ok("tok-123", KEY, 2), None))

                # serwer wysyła wiadomość od alice do klienta
                send_frame(s_end, build_frame(
                    c.TYPE_MSG, 0, 100, 0,
                    pm.encode_msg("alice", "Czesc", 123), KEY))

                ack = parse_frame(recv_frame(s_end))
                results["ack"] = pm.decode_ack(ack["payload"])

                client_msg = parse_frame(recv_frame(s_end))
                results["client_msg"] = pm.decode_msg(client_msg["payload"])
            except Exception as exc:  # zapisz, by test nie zawisł niemo
                results["error"] = repr(exc)

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0)
        cli._sock = c_end                       # wstrzykujemy gotowy socket

        cli.hello("TestClient/1.0")
        ok = cli.login("alice", "haslo")
        self.assertEqual(ok["queued_messages"], 2)
        self.assertEqual(cli._session_key, KEY)
        self.assertEqual(cli.session_token, "tok-123")

        received = []
        cli.on_message = lambda _cli, m: received.append(m)
        cli.start()

        self.assertTrue(_wait_until(lambda: received), "nie odebrano MSG od serwera")
        self.assertEqual(received[0]["text"], "Czesc")
        self.assertEqual(received[0]["recipient"], "alice")

        cli.send_message("bob", "Hej!")

        srv.join(timeout=2.0)
        self.assertNotIn("error", results, results.get("error"))
        self.assertEqual(results["hello_type"], c.TYPE_HELLO)
        self.assertEqual(results["auth_type"], c.TYPE_AUTH)
        self.assertEqual(results["ack"]["ack_msg_id"], 100)
        self.assertEqual(results["ack"]["status"], c.ACK_STATUS_DELIVERED)
        self.assertEqual(results["client_msg"]["recipient"], "bob")
        self.assertEqual(results["client_msg"]["text"], "Hej!")

        cli.close(send_bye=False)
        c_end.close()
        s_end.close()

    def test_login_failure_raises(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_ERR, 0, 1, 0,
                struct.pack("!H", c.ERR_AUTH_FAILED) + pack_string("zle haslo"), None))

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0)
        cli._sock = c_end
        cli.hello()
        from tcmp.errors import TCMPError
        with self.assertRaises(TCMPError) as ctx:
            cli.login("alice", "zle")
        self.assertEqual(ctx.exception.error_code, c.ERR_AUTH_FAILED)

        srv.join(timeout=2.0)
        cli.close(send_bye=False)
        c_end.close()
        s_end.close()

    def test_incoming_bad_hmac_rejected(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)
        wrong_key = b"\x99" * c.SESSION_KEY_LENGTH

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))
            # MSG podpisana NIEWŁAŚCIWYM kluczem - HMAC nie zgodzi się z KEY
            send_frame(s_end, build_frame(
                c.TYPE_MSG, 0, 50, 0,
                pm.encode_msg("alice", "spoofed", 1), wrong_key))

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0)
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")

        errors, messages = [], []
        cli.on_error = lambda _c, e: errors.append(e)
        cli.on_message = lambda _c, m: messages.append(m)
        cli.start()

        self.assertTrue(_wait_until(lambda: errors), "nie zgłoszono błędu HMAC")
        self.assertEqual(errors[0]["error_code"], c.ERR_HMAC_INVALID)
        self.assertTrue(errors[0]["fatal"])
        self.assertEqual(messages, [])          # sfałszowana wiadomość nie dostarczona

        srv.join(timeout=2.0)
        cli.close(send_bye=False)
        c_end.close()
        s_end.close()


class TestClientFileTransfer(unittest.TestCase):
    def test_send_multifragment_file(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)
        # > 65535B wymusza wiele fragmentów FILE.
        file_data = bytes(range(256)) * 800     # 204 800 B
        results = {}

        def fake_server():
            try:
                parse_frame(recv_frame(s_end))   # HELLO
                parse_frame(recv_frame(s_end))   # AUTH
                send_frame(s_end, build_frame(
                    c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))

                buf = ReassemblyBuffer()
                full = None
                while full is None:
                    p = parse_frame(recv_frame(s_end))
                    full = buf.receive(p["msg_id"], p["frag_num"], p["more_data"], p["payload"])
                results["file"] = pm.decode_file(full)
            except Exception as exc:
                results["error"] = repr(exc)

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0)
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")

        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        try:
            tmp.write(file_data)
            tmp.close()
            cli.send_file("bob", tmp.name)
            srv.join(timeout=3.0)
        finally:
            os.unlink(tmp.name)

        self.assertNotIn("error", results, results.get("error"))
        self.assertEqual(results["file"]["recipient"], "bob")
        self.assertEqual(results["file"]["mimetype_id"], c.MIMETYPE_PNG)
        self.assertEqual(results["file"]["total_filesize"], len(file_data))
        self.assertEqual(results["file"]["data"], file_data)

        cli.close(send_bye=False)
        c_end.close()
        s_end.close()

    def test_receive_multifragment_file(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)
        file_data = bytes(range(200)) * 1000    # 200 000 B

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))
            payload = pm.encode_file("alice", "foto.jpg", c.MIMETYPE_JPEG, file_data, 1)
            for frag in fragment_payload(payload):
                flags = c.FLAG_MORE_DATA if frag.more_data else 0
                send_frame(s_end, build_frame(
                    c.TYPE_FILE, flags, 77, frag.frag_num, frag.data, KEY))
            parse_frame(recv_frame(s_end))   # ACK od klienta

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0)
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")

        files = []
        cli.on_file = lambda _c, f: files.append(f)
        cli.start()

        self.assertTrue(_wait_until(lambda: files, timeout=3.0), "nie odebrano pliku")
        self.assertEqual(files[0]["filename"], "foto.jpg")
        self.assertEqual(files[0]["mimetype_id"], c.MIMETYPE_JPEG)
        self.assertEqual(files[0]["data"], file_data)

        srv.join(timeout=3.0)
        cli.close(send_bye=False)
        c_end.close()
        s_end.close()


class TestClientAckTracking(unittest.TestCase):
    def test_ack_resolves_pending(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))
            msg = parse_frame(recv_frame(s_end))           # MSG od klienta
            send_frame(s_end, build_frame(                 # ACK z powrotem
                c.TYPE_ACK, 0, 999, 0,
                pm.encode_ack(msg["msg_id"], c.ACK_STATUS_DELIVERED), KEY))

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0, ping_interval=0)   # bez keep-alive
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")

        acks = []
        cli.on_ack = lambda _c, a: acks.append(a)

        mid = cli.send_message("bob", "hej")
        self.assertIn(mid, cli.pending_acks())
        cli.start()

        self.assertTrue(_wait_until(lambda: acks), "nie odebrano ACK")
        self.assertEqual(acks[0]["ack_msg_id"], mid)
        self.assertEqual(acks[0]["status"], c.ACK_STATUS_DELIVERED)
        self.assertEqual(acks[0]["kind"], "MSG")
        self.assertEqual(acks[0]["recipient"], "bob")
        self.assertNotIn(mid, cli.pending_acks())

        srv.join(timeout=2.0)
        cli.close(send_bye=False)
        c_end.close()
        s_end.close()


class TestClientKeepAlive(unittest.TestCase):
    def test_emits_ping_when_idle(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)
        seen = {}

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))
            # klient bezczynny -> powinien sam wysłać PING
            frame = parse_frame(recv_frame(s_end))
            seen["type"] = frame["type"]

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0, ping_interval=0.1, pong_timeout=5.0)
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")
        cli.start()

        srv.join(timeout=3.0)
        self.assertEqual(seen.get("type"), c.TYPE_PING)

        cli.close(send_bye=False)
        c_end.close()
        s_end.close()

    def test_disconnect_on_missing_pong(self):
        c_end, s_end = socket.socketpair()
        s_end.settimeout(2.0)

        def fake_server():
            parse_frame(recv_frame(s_end))   # HELLO
            parse_frame(recv_frame(s_end))   # AUTH
            send_frame(s_end, build_frame(
                c.TYPE_AUTH_OK, 0, 1, 0, _encode_auth_ok("tok", KEY, 0), None))
            time.sleep(1.0)                  # cisza: brak PONG na PING klienta

        srv = threading.Thread(target=fake_server)
        srv.start()

        cli = TCMPClient("localhost", 0, ping_interval=0.1, pong_timeout=0.2)
        cli._sock = c_end
        cli.hello()
        cli.login("alice", "haslo")

        lost = []
        cli.on_disconnect = lambda _c, reason: lost.append(reason)
        cli.start()

        self.assertTrue(_wait_until(lambda: lost, timeout=3.0),
                        "nie wykryto utraty połączenia")
        self.assertIn("PONG", lost[0])

        srv.join(timeout=2.0)
        cli.close(send_bye=False)
        c_end.close()
        s_end.close()


if __name__ == "__main__":
    unittest.main()
