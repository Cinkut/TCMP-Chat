import struct
from .constants import (
    PROTOCOL_VERSION, HEADER_LENGTH, OFFSET_LENGTH, FLAG_MORE_DATA,
    TYPE_MIN, TYPE_MAX, TYPE_ERR, TYPE_BYE, MAX_FRAME_PAYLOAD,
    ERR_UNSUPPORTED_VERSION, ERR_UNKNOWN_TYPE, ERR_MALFORMED_PAYLOAD,
    ERR_PAYLOAD_TOO_LARGE, ERR_HMAC_INVALID,
)
from .hmac_utils import PRE_AUTH_TYPES, ZERO_HMAC, compute_hmac, verify_frame
from .errors import TCMPError

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
    if type_ in PRE_AUTH_TYPES:
        hmac_bytes = ZERO_HMAC
    elif session_key is not None:
        hmac_bytes = compute_hmac(session_key, pre_hmac + payload)
    elif type_ in (TYPE_ERR, TYPE_BYE):
        # ERR/BYE mogą wystąpić w fazie pre-auth, zanim powstanie session_key
        # (np. ERR_UNSUPPORTED_VERSION na złym HELLO, ERR_AUTH_FAILED /
        # ERR_AUTH_LIMIT na nieudanym AUTH, BYE reason=0x01 po timeoucie AUTH).
        # Po ustanowieniu sesji niosą prawdziwy HMAC (gałąź wyżej).
        hmac_bytes = ZERO_HMAC
    else:
        # Ochrona przed cichym wysłaniem ramki post-auth bez integralności.
        raise ValueError(
            f"session_key wymagany dla ramki typu 0x{type_:02X} (poza PRE_AUTH_TYPES)"
        )
    return pre_hmac + hmac_bytes + payload


def parse_frame(data: bytes) -> dict:
    if len(data) < HEADER_LENGTH:
        raise TCMPError(
            ERR_MALFORMED_PAYLOAD, f"nagłówek za krótki: {len(data)} < {HEADER_LENGTH}"
        )
    ver, type_, flags, msg_id, length, frag_num = struct.unpack_from(_PRE_HMAC_FMT, data)
    if len(data) < HEADER_LENGTH + length:
        raise TCMPError(
            ERR_MALFORMED_PAYLOAD,
            f"payload obcięty: jest {len(data) - HEADER_LENGTH}B, deklarowano {length}B",
        )
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


def validate_frame(
    parsed: dict,
    *,
    frame_bytes: bytes | None = None,
    session_key: bytes | None = None,
) -> None:
    """Waliduje ramkę wg reguł struktury ze specyfikacji (Etap1 §3.4).

    Sprawdza wyłącznie reguły możliwe do oceny z samej ramki: VER, TYPE,
    bity zarezerwowane FLAGS i górny limit LENGTH. Walidacja pól payloadu
    per-TYPE (suma pól, UTF-8, total_filesize) należy do warstwy payloads,
    a reguły stanowe (duplikat MSG_ID, FRAG_NUM) do warstwy sesji.

    Gdy podano ``session_key`` i ramka nie jest pre-auth, weryfikuje też HMAC
    (wymaga ``frame_bytes``). Rzuca ``TCMPError`` z odpowiednim kodem.
    """
    if parsed['ver'] != PROTOCOL_VERSION:
        raise TCMPError(ERR_UNSUPPORTED_VERSION, f"VER=0x{parsed['ver']:02X}")
    if not (TYPE_MIN <= parsed['type'] <= TYPE_MAX):
        raise TCMPError(ERR_UNKNOWN_TYPE, f"TYPE=0x{parsed['type']:02X}")
    if parsed['flags'] & ~FLAG_MORE_DATA:
        raise TCMPError(
            ERR_MALFORMED_PAYLOAD,
            f"zarezerwowane bity FLAGS ustawione: 0x{parsed['flags']:02X}",
        )
    if parsed['length'] > MAX_FRAME_PAYLOAD:
        raise TCMPError(
            ERR_PAYLOAD_TOO_LARGE, f"LENGTH={parsed['length']} > {MAX_FRAME_PAYLOAD}"
        )
    if len(parsed['payload']) != parsed['length']:
        raise TCMPError(
            ERR_MALFORMED_PAYLOAD,
            f"payload {len(parsed['payload'])}B != LENGTH {parsed['length']}B",
        )
    if session_key is not None and parsed['type'] not in PRE_AUTH_TYPES:
        if frame_bytes is None:
            raise ValueError("frame_bytes wymagane do weryfikacji HMAC")
        if not verify_frame(frame_bytes, session_key):
            raise TCMPError(ERR_HMAC_INVALID, f"HMAC niezgodny dla MSG_ID={parsed['msg_id']}")


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
    if length > MAX_FRAME_PAYLOAD:
        # Odrzuć przed alokacją/czytaniem - ochrona przed DoS (LENGTH do ~4 GB).
        raise TCMPError(
            ERR_PAYLOAD_TOO_LARGE, f"deklarowany LENGTH={length} > {MAX_FRAME_PAYLOAD}"
        )
    payload = _recv_exact(sock, length)
    return header + payload


def send_frame(sock, frame: bytes) -> None:
    sock.sendall(frame)
