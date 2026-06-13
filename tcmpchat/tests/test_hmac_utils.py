"""Testy integralności HMAC-SHA256 ramek."""
import hashlib
import hmac as _hmac
import unittest

from tcmp import constants as c
from tcmp import hmac_utils as h


KEY = b"\x11" * c.SESSION_KEY_LENGTH


class TestComputeHmac(unittest.TestCase):
    def test_output_is_32_bytes(self):
        self.assertEqual(len(h.compute_hmac(KEY, b"abc")), 32)

    def test_matches_stdlib(self):
        expected = _hmac.new(KEY, b"hello", hashlib.sha256).digest()
        self.assertEqual(h.compute_hmac(KEY, b"hello"), expected)

    def test_deterministic(self):
        self.assertEqual(h.compute_hmac(KEY, b"x"), h.compute_hmac(KEY, b"x"))

    def test_different_data_differs(self):
        self.assertNotEqual(h.compute_hmac(KEY, b"a"), h.compute_hmac(KEY, b"b"))

    def test_different_key_differs(self):
        other = b"\x22" * 32
        self.assertNotEqual(h.compute_hmac(KEY, b"a"), h.compute_hmac(other, b"a"))


class TestVerifyHmac(unittest.TestCase):
    def test_accepts_valid(self):
        mac = h.compute_hmac(KEY, b"data")
        self.assertTrue(h.verify_hmac(KEY, b"data", mac))

    def test_rejects_tampered_data(self):
        mac = h.compute_hmac(KEY, b"data")
        self.assertFalse(h.verify_hmac(KEY, b"DATA", mac))

    def test_rejects_wrong_key(self):
        mac = h.compute_hmac(KEY, b"data")
        self.assertFalse(h.verify_hmac(b"\x00" * 32, b"data", mac))


class TestVerifyFrame(unittest.TestCase):
    def _make_frame(self, pre_hmac: bytes, payload: bytes, key: bytes) -> bytes:
        mac = h.compute_hmac(key, pre_hmac + payload)
        return pre_hmac + mac + payload

    def test_valid_frame_passes(self):
        pre = b"\x01" * c.OFFSET_HMAC          # 17B przed polem HMAC
        payload = b"payload-bytes"
        frame = self._make_frame(pre, payload, KEY)
        self.assertEqual(len(frame[:c.OFFSET_HMAC]), c.OFFSET_HMAC)
        self.assertTrue(h.verify_frame(frame, KEY))

    def test_tampered_payload_fails(self):
        pre = b"\x01" * c.OFFSET_HMAC
        frame = self._make_frame(pre, b"payload-bytes", KEY)
        tampered = bytearray(frame)
        tampered[-1] ^= 0xFF
        self.assertFalse(h.verify_frame(bytes(tampered), KEY))

    def test_tampered_header_fails(self):
        pre = b"\x01" * c.OFFSET_HMAC
        frame = self._make_frame(pre, b"abc", KEY)
        tampered = bytearray(frame)
        tampered[0] ^= 0xFF
        self.assertFalse(h.verify_frame(bytes(tampered), KEY))


class TestPreAuthConstants(unittest.TestCase):
    def test_pre_auth_types(self):
        self.assertEqual(
            h.PRE_AUTH_TYPES,
            frozenset({c.TYPE_HELLO, c.TYPE_AUTH, c.TYPE_AUTH_OK}),
        )

    def test_zero_hmac(self):
        self.assertEqual(h.ZERO_HMAC, b"\x00" * 32)
        self.assertEqual(len(h.ZERO_HMAC), c.SIZE_HMAC)


if __name__ == "__main__":
    unittest.main()
