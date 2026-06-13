"""Kodowanie i dekodowanie payloadów ramek TCMP po stronie klienta.

Każda funkcja `encode_*` zwraca surowy payload (bez nagłówka 49B) gotowy
do przekazania do `frame.build_frame`, a każda `decode_*` przyjmuje payload
zwrócony przez `frame.parse_frame`["payload"].

Moduł jest świadomie kliencki - serwer (Osoba A) ma własną walidację pól
w warstwie sesji. Docelowo może zostać przeniesiony do wspólnego
`tcmp/payloads.py` po uzgodnieniu z zespołem.
"""
import struct

from tcmp import constants as c
from tcmp.frame import pack_string, unpack_string


# --------------------------------------------------------------------------- #
# HELLO (0x01)  C -> S
# --------------------------------------------------------------------------- #
def encode_hello(client_agent: str, protocol_version: int = c.PROTOCOL_VERSION) -> bytes:
    agent = client_agent.encode("utf-8")
    if len(agent) > c.MAX_CLIENT_AGENT:
        raise ValueError(f"client_agent > {c.MAX_CLIENT_AGENT}B")
    return struct.pack("!B", protocol_version) + pack_string(client_agent)


# --------------------------------------------------------------------------- #
# AUTH (0x02)  C -> S
# --------------------------------------------------------------------------- #
def encode_auth(username: str, password: str = "", resume_token: bytes = b"") -> bytes:
    if len(username.encode("utf-8")) > c.MAX_USERNAME:
        raise ValueError(f"username > {c.MAX_USERNAME}B")
    out = pack_string(username) + pack_string(password)
    out += struct.pack("!H", len(resume_token)) + resume_token
    return out


# --------------------------------------------------------------------------- #
# AUTH_OK (0x03)  S -> C
# --------------------------------------------------------------------------- #
def decode_auth_ok(payload: bytes) -> dict:
    session_token, off = unpack_string(payload, 0)
    (key_len,) = struct.unpack_from("!H", payload, off)
    off += 2
    session_key = payload[off:off + key_len]
    off += key_len
    (queued,) = struct.unpack_from("!I", payload, off)
    return {
        "session_token": session_token,
        "session_key": session_key,
        "queued_messages": queued,
    }


# --------------------------------------------------------------------------- #
# MSG (0x04)  C <-> S
# --------------------------------------------------------------------------- #
def encode_msg(recipient: str, text: str, timestamp_ms: int) -> bytes:
    if len(recipient.encode("utf-8")) > c.MAX_RECIPIENT:
        raise ValueError(f"recipient > {c.MAX_RECIPIENT}B")
    out = pack_string(recipient)
    out += struct.pack("!Q", timestamp_ms)
    out += pack_string(text)
    return out


def decode_msg(payload: bytes) -> dict:
    recipient, off = unpack_string(payload, 0)
    (timestamp_ms,) = struct.unpack_from("!Q", payload, off)
    off += 8
    text, off = unpack_string(payload, off)
    return {"recipient": recipient, "timestamp_ms": timestamp_ms, "text": text}


# --------------------------------------------------------------------------- #
# FILE (0x05)  C <-> S
# --------------------------------------------------------------------------- #
# Payload (przed fragmentacją): recipient | timestamp | filename | mimetype_id |
# total_filesize | chunk_data. Cały payload jest następnie cięty na fragmenty
# przez warstwę fragmentacji (jak MSG) - metadane są w bajtach fragmentu 0,
# a reassembly skleja strumień z powrotem przed decode_file.
def encode_file(recipient: str, filename: str, mimetype_id: int,
                file_bytes: bytes, timestamp_ms: int) -> bytes:
    if len(recipient.encode("utf-8")) > c.MAX_RECIPIENT:
        raise ValueError(f"recipient > {c.MAX_RECIPIENT}B")
    if len(filename.encode("utf-8")) > c.MAX_FILENAME:
        raise ValueError(f"filename > {c.MAX_FILENAME}B")
    if mimetype_id not in (c.MIMETYPE_JPEG, c.MIMETYPE_PNG):
        raise ValueError(f"nieobsługiwany mimetype_id=0x{mimetype_id:02X}")
    if len(file_bytes) > c.MAX_FILE_SIZE:
        raise ValueError(f"plik {len(file_bytes)}B > limit {c.MAX_FILE_SIZE}B")
    out = pack_string(recipient)
    out += struct.pack("!Q", timestamp_ms)
    out += pack_string(filename)
    out += struct.pack("!B", mimetype_id)
    out += struct.pack("!I", len(file_bytes))
    out += file_bytes
    return out


def decode_file(payload: bytes) -> dict:
    recipient, off = unpack_string(payload, 0)
    (timestamp_ms,) = struct.unpack_from("!Q", payload, off)
    off += 8
    filename, off = unpack_string(payload, off)
    (mimetype_id,) = struct.unpack_from("!B", payload, off)
    off += 1
    (total_filesize,) = struct.unpack_from("!I", payload, off)
    off += 4
    data = payload[off:]
    return {
        "recipient": recipient,
        "timestamp_ms": timestamp_ms,
        "filename": filename,
        "mimetype_id": mimetype_id,
        "total_filesize": total_filesize,
        "data": data,
    }


# --------------------------------------------------------------------------- #
# ACK (0x06)  C <-> S
# --------------------------------------------------------------------------- #
def encode_ack(ack_msg_id: int, status: int) -> bytes:
    return struct.pack("!QB", ack_msg_id, status)


def decode_ack(payload: bytes) -> dict:
    ack_msg_id, status = struct.unpack_from("!QB", payload, 0)
    return {"ack_msg_id": ack_msg_id, "status": status}


# --------------------------------------------------------------------------- #
# ERR (0x09)  S -> C
# --------------------------------------------------------------------------- #
def decode_err(payload: bytes) -> dict:
    (error_code,) = struct.unpack_from("!H", payload, 0)
    message, _ = unpack_string(payload, 2)
    return {
        "error_code": error_code,
        "name": c.ERR_NAMES.get(error_code, f"0x{error_code:04X}"),
        "message": message,
        "fatal": error_code in c.FATAL_ERRORS,
    }


# --------------------------------------------------------------------------- #
# BYE (0x0A)  C <-> S
# --------------------------------------------------------------------------- #
def encode_bye(reason: int = c.BYE_REASON_CLEAN) -> bytes:
    return struct.pack("!B", reason)


def decode_bye(payload: bytes) -> dict:
    (reason,) = struct.unpack_from("!B", payload, 0)
    return {"reason": reason}
