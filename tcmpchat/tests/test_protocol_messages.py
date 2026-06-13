"""Round-trip kodowania/dekodowania payloadów klienta TCMP."""
import struct
import unittest

from tcmp import constants as c
from client import protocol_messages as pm


class TestHello(unittest.TestCase):
    def test_encode_structure(self):
        payload = pm.encode_hello("MyChatClient/1.0")
        self.assertEqual(payload[0], c.PROTOCOL_VERSION)
        (agent_len,) = struct.unpack_from("!H", payload, 1)
        self.assertEqual(agent_len, len("MyChatClient/1.0"))

    def test_rejects_too_long_agent(self):
        with self.assertRaises(ValueError):
            pm.encode_hello("x" * (c.MAX_CLIENT_AGENT + 1))


class TestAuth(unittest.TestCase):
    def test_encode_no_resume_token(self):
        payload = pm.encode_auth("alice", "secret")
        # username(2+5) + password(2+6) + resume_token_len(2)=0
        self.assertEqual(payload[-2:], b"\x00\x00")

    def test_encode_with_resume_token(self):
        token = b"\xAA\xBB\xCC"
        payload = pm.encode_auth("alice", "", resume_token=token)
        self.assertEqual(payload[-2 - len(token):], struct.pack("!H", 3) + token)

    def test_rejects_too_long_username(self):
        with self.assertRaises(ValueError):
            pm.encode_auth("u" * (c.MAX_USERNAME + 1), "x")


class TestAuthOk(unittest.TestCase):
    def test_roundtrip(self):
        token = "session-token-xyz"
        key = b"\x07" * c.SESSION_KEY_LENGTH
        from tcmp.frame import pack_string
        payload = pack_string(token) + struct.pack("!H", len(key)) + key + struct.pack("!I", 5)
        decoded = pm.decode_auth_ok(payload)
        self.assertEqual(decoded["session_token"], token)
        self.assertEqual(decoded["session_key"], key)
        self.assertEqual(decoded["queued_messages"], 5)


class TestMsg(unittest.TestCase):
    def test_roundtrip(self):
        payload = pm.encode_msg("bob", "Hej!", 1_700_000_000_000)
        decoded = pm.decode_msg(payload)
        self.assertEqual(decoded["recipient"], "bob")
        self.assertEqual(decoded["text"], "Hej!")
        self.assertEqual(decoded["timestamp_ms"], 1_700_000_000_000)

    def test_roundtrip_utf8(self):
        decoded = pm.decode_msg(pm.encode_msg("łukasz", "zażółć gęślą jaźń", 1))
        self.assertEqual(decoded["recipient"], "łukasz")
        self.assertEqual(decoded["text"], "zażółć gęślą jaźń")

    def test_rejects_too_long_recipient(self):
        with self.assertRaises(ValueError):
            pm.encode_msg("r" * (c.MAX_RECIPIENT + 1), "hi", 1)


class TestFile(unittest.TestCase):
    def test_roundtrip(self):
        data = bytes(range(256)) * 4
        payload = pm.encode_file("bob", "kot.png", c.MIMETYPE_PNG, data, 1_700_000_000_000)
        decoded = pm.decode_file(payload)
        self.assertEqual(decoded["recipient"], "bob")
        self.assertEqual(decoded["filename"], "kot.png")
        self.assertEqual(decoded["mimetype_id"], c.MIMETYPE_PNG)
        self.assertEqual(decoded["total_filesize"], len(data))
        self.assertEqual(decoded["data"], data)

    def test_rejects_oversize_file(self):
        with self.assertRaises(ValueError):
            pm.encode_file("bob", "big.jpg", c.MIMETYPE_JPEG,
                           b"\x00" * (c.MAX_FILE_SIZE + 1), 1)

    def test_rejects_bad_mimetype(self):
        with self.assertRaises(ValueError):
            pm.encode_file("bob", "f.gif", 0x09, b"x", 1)

    def test_rejects_too_long_filename(self):
        with self.assertRaises(ValueError):
            pm.encode_file("bob", "f" * (c.MAX_FILENAME + 1) + ".png",
                           c.MIMETYPE_PNG, b"x", 1)


class TestAck(unittest.TestCase):
    def test_roundtrip_delivered(self):
        decoded = pm.decode_ack(pm.encode_ack(42, c.ACK_STATUS_DELIVERED))
        self.assertEqual(decoded["ack_msg_id"], 42)
        self.assertEqual(decoded["status"], c.ACK_STATUS_DELIVERED)

    def test_roundtrip_queued(self):
        decoded = pm.decode_ack(pm.encode_ack(7, c.ACK_STATUS_QUEUED))
        self.assertEqual(decoded["status"], c.ACK_STATUS_QUEUED)


class TestErr(unittest.TestCase):
    def test_decode(self):
        from tcmp.frame import pack_string
        payload = struct.pack("!H", c.ERR_AUTH_FAILED) + pack_string("zły login")
        decoded = pm.decode_err(payload)
        self.assertEqual(decoded["error_code"], c.ERR_AUTH_FAILED)
        self.assertEqual(decoded["name"], "ERR_AUTH_FAILED")
        self.assertEqual(decoded["message"], "zły login")
        self.assertFalse(decoded["fatal"])

    def test_fatal_flag(self):
        from tcmp.frame import pack_string
        payload = struct.pack("!H", c.ERR_HMAC_INVALID) + pack_string("bad mac")
        self.assertTrue(pm.decode_err(payload)["fatal"])


class TestBye(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(pm.decode_bye(pm.encode_bye(c.BYE_REASON_TIMEOUT))["reason"],
                         c.BYE_REASON_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
