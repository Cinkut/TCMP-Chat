import hmac as _hmac
import hashlib
from .constants import TYPE_HELLO, TYPE_AUTH, TYPE_AUTH_OK, OFFSET_HMAC, HEADER_LENGTH

PRE_AUTH_TYPES: frozenset[int] = frozenset({TYPE_HELLO, TYPE_AUTH, TYPE_AUTH_OK})
ZERO_HMAC: bytes = b'\x00' * 32


def compute_hmac(session_key: bytes, data: bytes) -> bytes:
    return _hmac.new(session_key, data, hashlib.sha256).digest()


def verify_hmac(session_key: bytes, data: bytes, expected: bytes) -> bool:
    return _hmac.compare_digest(compute_hmac(session_key, data), expected)


def verify_frame(frame_bytes: bytes, session_key: bytes) -> bool:
    pre_hmac = frame_bytes[:OFFSET_HMAC]
    stored_hmac = frame_bytes[OFFSET_HMAC:HEADER_LENGTH]
    payload = frame_bytes[HEADER_LENGTH:]
    return verify_hmac(session_key, pre_hmac + payload, stored_hmac)
