"""Klient protokołu TCMP.

Zakres MVP: nawiązanie połączenia (TCP, opcjonalnie TLS), HELLO, AUTH
hasłem, odbiór AUTH_OK, wysyłanie i odbiór MSG z automatycznym ACK oraz
keep-alive PING/PONG. Transfer plików (FILE) i session resume są poza tym
etapem.

Typowe użycie:

    cli = TCMPClient("localhost", 7000)
    cli.connect()
    cli.hello()
    cli.login("alice", "secret")
    cli.on_message = lambda sender_unused, m: print(m["text"])
    cli.start()
    cli.send_message("bob", "Hej!")
    ...
    cli.close()
"""
import os
import socket
import ssl
import threading
import time

from tcmp import constants as c
from tcmp import frame as fr
from tcmp.errors import TCMPError
from tcmp.fragment import ReassemblyBuffer, fragment_payload

from . import protocol_messages as pm


def _now_ms() -> int:
    return int(time.time() * 1000)


# Rozszerzenie pliku -> mimetype_id obsługiwany przez protokół.
_MIMETYPE_BY_EXT = {
    ".jpg": c.MIMETYPE_JPEG,
    ".jpeg": c.MIMETYPE_JPEG,
    ".png": c.MIMETYPE_PNG,
}


def _mimetype_for(filename: str) -> int:
    ext = os.path.splitext(filename)[1].lower()
    try:
        return _MIMETYPE_BY_EXT[ext]
    except KeyError:
        raise ValueError(f"nieobsługiwane rozszerzenie pliku: {ext or '(brak)'}")


class TCMPClient:
    def __init__(self, host: str, port: int = c.DEFAULT_PORT, *,
                 ping_interval: float = c.PING_INTERVAL,
                 pong_timeout: float = c.PONG_TIMEOUT):
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None

        # Stan sesji ustalany po AUTH_OK.
        self.username: str | None = None
        self.session_token: str | None = None
        self._session_key: bytes | None = None
        self.queued_messages = 0

        # MSG_ID monotonicznie rosnący per sesja, inicjowany od 1 (spec §5.5).
        self._next_id = 1
        self._id_lock = threading.Lock()
        self._send_lock = threading.Lock()

        # Śledzenie ACK: MSG_ID wysłanych MSG/FILE czekających na potwierdzenie.
        self._pending: dict[int, dict] = {}
        self._pending_lock = threading.Lock()

        # Keep-alive (spec §4.5): PING co `ping_interval` s bezczynności,
        # brak PONG przez `pong_timeout` s -> utrata połączenia.
        self._ping_interval = ping_interval
        self._pong_timeout = pong_timeout
        self._ka_lock = threading.Lock()
        self._last_activity = time.monotonic()
        self._awaiting_pong = False
        self._ping_sent_at = 0.0
        self._keepalive: threading.Thread | None = None

        self._reassembly = ReassemblyBuffer()
        self._reader: threading.Thread | None = None
        self._running = False

        # Callbacki ustawiane przez użytkownika klasy.
        self.on_message = None     # (client, dict) -> None
        self.on_file = None        # (client, dict) -> None
        self.on_error = None       # (client, dict) -> None
        self.on_ack = None         # (client, dict) -> None
        self.on_disconnect = None  # (client, str) -> None  (utrata połączenia)

    # ------------------------------------------------------------------ #
    # Połączenie
    # ------------------------------------------------------------------ #
    def connect(self, *, use_tls: bool = False, cafile: str | None = None) -> None:
        raw = socket.create_connection((self.host, self.port))
        if use_tls:
            # Spec wymaga TLS 1.3 i weryfikacji łańcucha certyfikatów.
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self._sock = raw

    def _next_msg_id(self) -> int:
        with self._id_lock:
            mid = self._next_id
            self._next_id += 1
            return mid

    def _send(self, type_: int, payload: bytes, *, flags: int = 0,
              frag_num: int = 0, msg_id: int | None = None) -> int:
        if self._sock is None:
            raise RuntimeError("brak połączenia - wywołaj connect()")
        if msg_id is None:
            msg_id = self._next_msg_id()
        frame = fr.build_frame(type_, flags, msg_id, frag_num, payload, self._session_key)
        with self._send_lock:
            fr.send_frame(self._sock, frame)
        self._mark_activity()
        return msg_id

    def _mark_activity(self) -> None:
        with self._ka_lock:
            self._last_activity = time.monotonic()

    # ------------------------------------------------------------------ #
    # Handshake
    # ------------------------------------------------------------------ #
    def hello(self, client_agent: str = "TCMPClient/1.0") -> None:
        self._send(c.TYPE_HELLO, pm.encode_hello(client_agent))

    def login(self, username: str, password: str) -> dict:
        """Uwierzytelnia hasłem i zapisuje token + klucz sesyjny z AUTH_OK."""
        self._send(c.TYPE_AUTH, pm.encode_auth(username, password))
        reply = fr.parse_frame(fr.recv_frame(self._sock))

        if reply["type"] == c.TYPE_ERR:
            info = pm.decode_err(reply["payload"])
            raise TCMPError(info["error_code"], info["message"])
        if reply["type"] != c.TYPE_AUTH_OK:
            raise TCMPError(c.ERR_MALFORMED_PAYLOAD,
                            f"oczekiwano AUTH_OK, otrzymano 0x{reply['type']:02X}")

        ok = pm.decode_auth_ok(reply["payload"])
        self.username = username
        self.session_token = ok["session_token"]
        self._session_key = ok["session_key"]
        self.queued_messages = ok["queued_messages"]
        return ok

    # ------------------------------------------------------------------ #
    # Wysyłanie wiadomości
    # ------------------------------------------------------------------ #
    def send_message(self, recipient: str, text: str) -> int:
        """Wysyła MSG; przy długim tekście dzieli na fragmenty (wspólny MSG_ID)."""
        if self._session_key is None:
            raise RuntimeError("nie zalogowano - brak session_key")
        payload = pm.encode_msg(recipient, text, _now_ms())
        msg_id = self._next_msg_id()

        fragments = fragment_payload(payload)
        for frag in fragments:
            flags = c.FLAG_MORE_DATA if frag.more_data else 0
            self._send(c.TYPE_MSG, frag.data, flags=flags,
                       frag_num=frag.frag_num, msg_id=msg_id)
        self._register_pending(msg_id, "MSG", recipient)
        return msg_id

    def send_file(self, recipient: str, filepath: str) -> int:
        """Wysyła plik graficzny (JPEG/PNG) jako sfragmentowane ramki FILE."""
        if self._session_key is None:
            raise RuntimeError("nie zalogowano - brak session_key")
        mimetype_id = _mimetype_for(filepath)
        with open(filepath, "rb") as fh:
            file_bytes = fh.read()
        filename = os.path.basename(filepath)
        payload = pm.encode_file(recipient, filename, mimetype_id, file_bytes, _now_ms())
        msg_id = self._next_msg_id()

        for frag in fragment_payload(payload):
            flags = c.FLAG_MORE_DATA if frag.more_data else 0
            self._send(c.TYPE_FILE, frag.data, flags=flags,
                       frag_num=frag.frag_num, msg_id=msg_id)
        self._register_pending(msg_id, "FILE", recipient)
        return msg_id

    # ------------------------------------------------------------------ #
    # Śledzenie ACK
    # ------------------------------------------------------------------ #
    def _register_pending(self, msg_id: int, kind: str, recipient: str) -> None:
        with self._pending_lock:
            self._pending[msg_id] = {
                "kind": kind, "recipient": recipient,
                "sent_at": time.monotonic(), "status": None,
            }

    def pending_acks(self) -> set[int]:
        """MSG_ID wysłanych MSG/FILE, dla których nie nadszedł jeszcze ACK."""
        with self._pending_lock:
            return set(self._pending)

    def _resolve_ack(self, ack: dict) -> dict:
        # Zdejmuje MSG_ID z oczekujących i wzbogaca ACK o metadane wysyłki.
        with self._pending_lock:
            info = self._pending.pop(ack["ack_msg_id"], None)
        merged = dict(ack)
        if info is not None:
            merged["kind"] = info["kind"]
            merged["recipient"] = info["recipient"]
        return merged

    def ping(self) -> None:
        self._send(c.TYPE_PING, b"")

    def bye(self, reason: int = c.BYE_REASON_CLEAN) -> None:
        self._send(c.TYPE_BYE, pm.encode_bye(reason))

    # ------------------------------------------------------------------ #
    # Pętla odbioru (wątek w tle)
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._reader = threading.Thread(target=self._recv_loop, daemon=True)
        self._reader.start()
        if self._ping_interval > 0:
            self._keepalive = threading.Thread(target=self._keepalive_loop, daemon=True)
            self._keepalive.start()

    def _recv_loop(self) -> None:
        try:
            while self._running:
                raw = fr.recv_frame(self._sock)
                # Każda odebrana ramka resetuje licznik bezczynności i oczekiwanie
                # na PONG (spec §4.5).
                with self._ka_lock:
                    self._last_activity = time.monotonic()
                    self._awaiting_pong = False
                try:
                    parsed = fr.parse_frame(raw)
                    # Walidacja struktury + integralności (HMAC) każdej odebranej
                    # ramki. validate_frame weryfikuje HMAC tylko dla ramek
                    # po-AUTH gdy mamy już session_key.
                    fr.validate_frame(parsed, frame_bytes=raw,
                                      session_key=self._session_key)
                except TCMPError as err:
                    self._report_error(err)
                    if err.fatal:
                        break          # błąd fatalny -> zamknięcie połączenia
                    continue           # niefatalny -> pomiń ramkę, czytaj dalej
                self._dispatch(parsed)
        except (ConnectionError, OSError):
            pass  # połączenie zamknięte - kończymy wątek
        finally:
            self._running = False

    def _report_error(self, err: TCMPError) -> None:
        if self.on_error:
            self.on_error(self, {
                "error_code": err.error_code,
                "name": c.ERR_NAMES.get(err.error_code, f"0x{err.error_code:04X}"),
                "message": str(err),
                "fatal": err.fatal,
            })

    def _dispatch(self, p: dict) -> None:
        t = p["type"]
        if t == c.TYPE_MSG:
            self._handle_reassembled(p, c.TYPE_MSG)
        elif t == c.TYPE_FILE:
            self._handle_reassembled(p, c.TYPE_FILE)
        elif t == c.TYPE_ACK:
            ack = self._resolve_ack(pm.decode_ack(p["payload"]))
            if self.on_ack:
                self.on_ack(self, ack)
        elif t == c.TYPE_PING:
            self._send(c.TYPE_PONG, b"")
        elif t == c.TYPE_PONG:
            pass
        elif t == c.TYPE_ERR:
            if self.on_error:
                self.on_error(self, pm.decode_err(p["payload"]))
        elif t == c.TYPE_BYE:
            self._running = False

    def _handle_reassembled(self, p: dict, kind: int) -> None:
        # Składanie fragmentów MSG/FILE; pełny payload dopiero po ostatnim.
        full = self._reassembly.receive(
            p["msg_id"], p["frag_num"], p["more_data"], p["payload"]
        )
        if full is None:
            return
        # ACK na poziomie aplikacyjnym (odbiorca online -> delivered).
        self._send(c.TYPE_ACK, pm.encode_ack(p["msg_id"], c.ACK_STATUS_DELIVERED))
        if kind == c.TYPE_MSG:
            if self.on_message:
                self.on_message(self, pm.decode_msg(full))
        else:  # TYPE_FILE
            if self.on_file:
                self.on_file(self, pm.decode_file(full))

    # ------------------------------------------------------------------ #
    # Keep-alive (PING/PONG)
    # ------------------------------------------------------------------ #
    def _keepalive_loop(self) -> None:
        # Tick na tyle mały, by reagować w okolicach progów (i szybko w testach).
        tick = max(0.02, min(self._ping_interval, self._pong_timeout) / 5)
        while self._running:
            time.sleep(tick)
            now = time.monotonic()
            with self._ka_lock:
                awaiting = self._awaiting_pong
                idle = now - self._last_activity
                since_ping = now - self._ping_sent_at
            if awaiting:
                if since_ping >= self._pong_timeout:
                    # Brak PONG w oknie -> utrata połączenia (spec §4.5).
                    self._on_connection_lost("brak PONG w oknie keep-alive")
                    break
            elif idle >= self._ping_interval:
                with self._ka_lock:
                    self._awaiting_pong = True
                    self._ping_sent_at = now
                try:
                    self._send(c.TYPE_PING, b"")
                except OSError:
                    self._on_connection_lost("błąd wysyłania PING")
                    break

    def _on_connection_lost(self, reason: str) -> None:
        self._running = False
        if self.on_disconnect:
            self.on_disconnect(self, reason)

    # ------------------------------------------------------------------ #
    # Zamknięcie
    # ------------------------------------------------------------------ #
    def close(self, *, send_bye: bool = True) -> None:
        if send_bye and self._sock is not None and self._session_key is not None:
            try:
                self.bye(c.BYE_REASON_CLEAN)
            except OSError:
                pass
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
