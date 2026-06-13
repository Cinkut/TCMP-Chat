import struct
from .constants import (
    PROTOCOL_VERSION, HEADER_LENGTH, OFFSET_HMAC, OFFSET_LENGTH, FLAG_MORE_DATA,
)
from .hmac_utils import PRE_AUTH_TYPES, ZERO_HMAC, compute_hmac

_PRE_HMAC_FMT = '!BBBQIH'   # VER(1) TYPE(1) FLAGS(1) MSG_ID(8) LENGTH(4) FRAG_NUM(2) = 17B
_PRE_HMAC_SIZE = struct.calcsize(_PRE_HMAC_FMT)   # 17


def pack_string(s: str) -> bytes:
    encoded = s.encode('utf-8')
    return struct.pack('!H', len(encoded)) + encoded


def unpack_string(data: bytes, offset: int) -> tuple[str, int]:
    (length,) = struct.unpack_from('!H', data, offset)
    offset += 2
    text = data[offset:offset + length].decode('utf-8')
    return text, offset + length


def build_frame(
    type_: int,
    flags: int,
    msg_id: int,
    frag_num: int,
    payload: bytes,
    session_key: bytes | None = None,
) -> bytes:
    pre_hmac = struct.pack(
        _PRE_HMAC_FMT, PROTOCOL_VERSION, type_, flags, msg_id, len(payload), frag_num
    )
    if type_ in PRE_AUTH_TYPES or session_key is None:
        hmac_bytes = ZERO_HMAC
    else:
        hmac_bytes = compute_hmac(session_key, pre_hmac + payload)
    return pre_hmac + hmac_bytes + payload


def parse_frame(data: bytes) -> dict:
    if len(data) < HEADER_LENGTH:
        raise ValueError(f"Frame too short: {len(data)} < {HEADER_LENGTH}")
    ver, type_, flags, msg_id, length, frag_num = struct.unpack_from(_PRE_HMAC_FMT, data)
    hmac_val = data[_PRE_HMAC_SIZE:HEADER_LENGTH]
    payload = data[HEADER_LENGTH:HEADER_LENGTH + length]
    return {
        'ver':       ver,
        'type':      type_,
        'flags':     flags,
        'msg_id':    msg_id,
        'length':    length,
        'frag_num':  frag_num,
        'hmac':      hmac_val,
        'more_data': bool(flags & FLAG_MORE_DATA),
        'payload':   payload,
    }


def _recv_exact(sock, n: int) -> bytes:
    if n == 0:
        return b''
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock) -> bytes:
    header = _recv_exact(sock, HEADER_LENGTH)
    (length,) = struct.unpack_from('!I', header, OFFSET_LENGTH)
    payload = _recv_exact(sock, length)
    return header + payload


def send_frame(sock, frame: bytes) -> None:
    sock.sendall(frame)
