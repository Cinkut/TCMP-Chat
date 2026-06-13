"""Testy budowania, parsowania i odbioru ramek TCMP."""
import unittest

from tcmp import constants as c
from tcmp import frame as f
from tcmp import hmac_utils as h


KEY = b"\x33" * c.SESSION_KEY_LENGTH


class TestPackString(unittest.TestCase):
    def test_roundtrip_ascii(self):
        packed = f.pack_string("bob")
        text, end = f.unpack_string(packed, 0)
        self.assertEqual(text, "bob")
        self.assertEqual(end, len(packed))

    def test_length_prefix_is_byte_count(self):
        packed = f.pack_string("bob")
        self.assertEqual(packed[:2], b"\x00\x03")

    def test_utf8_multibyte_length_in_bytes(self):
        # "ł" = 2 bajty UTF-8, "ą" = 2 bajty -> 4 bajty, nie 2 znaki
        packed = f.pack_string("łą")
        self.assertEqual(packed[:2], b"\x00\x04")
        text, _ = f.unpack_string(packed, 0)
        self.assertEqual(text, "łą")

    def test_empty_string(self):
        packed = f.pack_string("")
        self.assertEqual(packed, b"\x00\x00")
        text, end = f.unpack_string(packed, 0)
        self.assertEqual(text, "")
        self.assertEqual(end, 2)

    def test_unpack_with_offset(self):
        data = b"\xAA\xBB" + f.pack_string("hi")
        text, end = f.unpack_string(data, 2)
        self.assertEqual(text, "hi")
        self.assertEqual(end, len(data))


class TestBuildParseRoundtrip(unittest.TestCase):
    def test_header_length_is_49(self):
        frame = f.build_frame(c.TYPE_PING, 0, 1, 0, b"")
        self.assertEqual(len(frame), c.HEADER_LENGTH)

    def test_roundtrip_fields(self):
        payload = b"hello-payload"
        frame = f.build_frame(c.TYPE_MSG, 0, 42, 0, payload, session_key=KEY)
        parsed = f.parse_frame(frame)
        self.assertEqual(parsed["ver"], c.PROTOCOL_VERSION)
        self.assertEqual(parsed["type"], c.TYPE_MSG)
        self.assertEqual(parsed["msg_id"], 42)
        self.assertEqual(parsed["length"], len(payload))
        self.assertEqual(parsed["frag_num"], 0)
        self.assertEqual(parsed["payload"], payload)

    def test_more_data_flag_parsed(self):
        frame = f.build_frame(c.TYPE_MSG, c.FLAG_MORE_DATA, 1, 0, b"x", session_key=KEY)
        parsed = f.parse_frame(frame)
        self.assertTrue(parsed["more_data"])

    def test_no_more_data_flag(self):
        frame = f.build_frame(c.TYPE_MSG, 0, 1, 0, b"x", session_key=KEY)
        parsed = f.parse_frame(frame)
        self.assertFalse(parsed["more_data"])

    def test_length_matches_payload(self):
        payload = b"a" * 1000
        frame = f.build_frame(c.TYPE_MSG, 0, 7, 0, payload, session_key=KEY)
        parsed = f.parse_frame(frame)
        self.assertEqual(parsed["length"], 1000)
        self.assertEqual(len(parsed["payload"]), 1000)

    def test_big_endian_msg_id(self):
        frame = f.build_frame(c.TYPE_MSG, 0, 0x0102030405060708, 0, b"", session_key=KEY)
        # MSG_ID zaczyna się na offsecie 0x03, big-endian
        self.assertEqual(frame[3:11], bytes.fromhex("0102030405060708"))

    def test_parse_too_short_raises(self):
        with self.assertRaises(ValueError):
            f.parse_frame(b"\x00" * 10)


class TestHmacBehaviour(unittest.TestCase):
    def test_post_auth_frame_has_real_hmac(self):
        frame = f.build_frame(c.TYPE_MSG, 0, 1, 0, b"data", session_key=KEY)
        parsed = f.parse_frame(frame)
        self.assertNotEqual(parsed["hmac"], h.ZERO_HMAC)
        self.assertTrue(h.verify_frame(frame, KEY))

    def test_pre_auth_types_get_zero_hmac(self):
        for t in (c.TYPE_HELLO, c.TYPE_AUTH, c.TYPE_AUTH_OK):
            frame = f.build_frame(t, 0, 1, 0, b"data", session_key=KEY)
            self.assertEqual(f.parse_frame(frame)["hmac"], h.ZERO_HMAC)

    def test_no_session_key_gives_zero_hmac(self):
        frame = f.build_frame(c.TYPE_MSG, 0, 1, 0, b"data", session_key=None)
        self.assertEqual(f.parse_frame(frame)["hmac"], h.ZERO_HMAC)

    def test_tampered_payload_fails_verify(self):
        frame = bytearray(f.build_frame(c.TYPE_MSG, 0, 1, 0, b"data", session_key=KEY))
        frame[-1] ^= 0xFF
        self.assertFalse(h.verify_frame(bytes(frame), KEY))


class _FakeSocket:
    """Minimalny socket zwracający zadane bajty w kawałkach po `chunk` B."""
    def __init__(self, data: bytes, chunk: int = 7):
        self._data = data
        self._pos = 0
        self._chunk = chunk
        self.sent = bytearray()

    def recv(self, n: int) -> bytes:
        take = min(n, self._chunk, len(self._data) - self._pos)
        out = self._data[self._pos:self._pos + take]
        self._pos += take
        return out

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


class TestSocketIO(unittest.TestCase):
    def test_recv_frame_reassembles_full_frame(self):
        original = f.build_frame(c.TYPE_MSG, 0, 99, 0, b"chunked-payload", session_key=KEY)
        sock = _FakeSocket(original, chunk=5)   # wymusza wiele recv()
        received = f.recv_frame(sock)
        self.assertEqual(received, original)

    def test_recv_frame_empty_payload(self):
        original = f.build_frame(c.TYPE_PING, 0, 1, 0, b"")
        sock = _FakeSocket(original, chunk=3)
        self.assertEqual(f.recv_frame(sock), original)

    def test_recv_closed_connection_raises(self):
        partial = f.build_frame(c.TYPE_PING, 0, 1, 0, b"")[:10]
        sock = _FakeSocket(partial, chunk=4)
        with self.assertRaises(ConnectionError):
            f.recv_frame(sock)

    def test_send_frame_writes_all_bytes(self):
        frame = f.build_frame(c.TYPE_PONG, 0, 1, 0, b"")
        sock = _FakeSocket(b"")
        f.send_frame(sock, frame)
        self.assertEqual(bytes(sock.sent), frame)


if __name__ == "__main__":
    unittest.main()
