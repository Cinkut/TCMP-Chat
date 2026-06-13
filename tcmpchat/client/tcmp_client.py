"""Klient protokołu TCMP.

Zakres: nawiązanie połączenia (TCP, opcjonalnie TLS), HELLO, AUTH hasłem,
odbiór AUTH_OK, wysyłanie i odbiór MSG/FILE z automatycznym ACK, fragmentacja,
keep-alive PING/PONG oraz session resume po zerwaniu połączenia.

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
                 pong_timeout: float = c.PONG_TIMEOUT,
                 auto_reconnect: bool = False,
                 reconnect_backoff: float = 1.0,
                 reconnect_max_attempts: int = 5):
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

        # Auto-reconnect (spec §4.5: po utracie połączenia klient może podjąć
        # session resume). Gdy włączone, utrata połączenia uruchamia wznawianie
        # sesji przez resume() z backoffem.
        self.auto_reconnect = auto_reconnect
        self._reconnect_backoff = reconnect_backoff
        self._reconnect_max_attempts = reconnect_max_attempts
        self._loss_lock = threading.Lock()
        self._handling_loss = False
        self._closing = False

        self._reassembly = ReassemblyBuffer()
        self._reader: threading.Thread | None = None
        self._running = False

        # Callbacki ustawiane przez użytkownika klasy.
        self.on_message = None     # (client, dict) -> None
        self.on_file = None        # (client, dict) -> None
        self.on_error = None       # (client, dict) -> None
        self.on_ack = None         # (client, dict) -> None
        self.on_disconnect = None  # (client, str) -> None  (utrata połączenia)
        self.on_reconnect = None   # (client, int) -> None  (udane wznowienie, nr próby)
        self.on_verbose = None     # (client, str) -> None  (diagnostyka --verbose)

    def _v(self, msg: str) -> None:
        if self.on_verbose:
            self.on_verbose(self, msg)

    # ------------------------------------------------------------------ #
    # Połączenie
    # ------------------------------------------------------------------ #
    def connect(self, *, use_tls: bool = False, cafile: str | None = None) -> None:
        # Zapamiętujemy opcje, by reconnect() (po zerwaniu) mógł je powtórzyć.
        self._tls_opts = {"use_tls": use_tls, "cafile": cafile}
        self._v(f"Łączenie z {self.host}:{self.port}...")
        raw = socket.create_connection((self.host, self.port))
        if use_tls:
            # Spec wymaga TLS 1.3 i weryfikacji łańcucha certyfikatów.
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
            if self.on_verbose:
                ci = self._sock.cipher()
                self._v(f"TLS handshake OK ({ci[1]}, {ci[0]})")
        else:
            self._sock = raw
            self._v("Połączono (bez TLS)")

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
        self._v("HELLO wysłane")

    def login(self, username: str, password: str) -> dict:
        """Uwierzytelnia hasłem i zapisuje token + klucz sesyjny z AUTH_OK."""
        self._send(c.TYPE_AUTH, pm.encode_auth(username, password))
        self._v("AUTH wysłane")
        return self._read_auth_reply(username)

    def resume(self) -> dict:
        """Wznawia sesję po zerwaniu, wysyłając AUTH z resume_token (bez hasła).

        Wymaga wcześniejszego udanego login() (mamy username + session_token).
        Serwer rotuje token i klucz - nowy AUTH_OK nadpisuje stan sesji.
        """
        if self.username is None or self.session_token is None:
            raise RuntimeError("resume wymaga wcześniejszego login()")
        # Nowa sesja: MSG_ID znów od 1, świeży bufor składania fragmentów.
        with self._id_lock:
            self._next_id = 1
        self._reassembly = ReassemblyBuffer()
        # Klucz starej sesji nie obowiązuje dla nowej ramki AUTH (pre-auth, ZERO_HMAC).
        self._session_key = None
        token_bytes = self.session_token.encode("utf-8")
        self._send(c.TYPE_AUTH, pm.encode_auth(self.username, "", resume_token=token_bytes))
        self._v("AUTH wysłane (resume_token)")
        return self._read_auth_reply(self.username)

    def reconnect(self) -> dict:
        """Ponownie nawiązuje połączenie (TCP+TLS) i wznawia sesję przez resume()."""
        opts = getattr(self, "_tls_opts", {"use_tls": False, "cafile": None})
        self.connect(**opts)
        self.hello()
        return self.resume()

    def _read_auth_reply(self, username: str) -> dict:
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
        self._v(f"AUTH_OK: queued={ok['queued_messages']}, "
                f"token={ok['session_token'][:4]}...")
        return ok

    # ------------------------------------------------------------------ #
    # Wysyłanie wiadomości
    # ------------------------------------------------------------------ #
    def send_message(self, recipient: str, text: str) -> int:
        """Wysyła MSG; przy długim tekście dzieli na fragmenty (wspólny MSG_ID)."""
        if self._session_key is None:
            raise RuntimeError("nie zalogowano - brak session_key")
        payload = pm.encode_msg(self.username, recipient, text, _now_ms())
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
        payload = pm.encode_file(self.username, recipient, filename, mimetype_id,
                                 file_bytes, _now_ms())
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
            self._trigger_loss("zerwane połączenie (odczyt)")
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
                    self._trigger_loss("brak PONG w oknie keep-alive")
                    break
            elif idle >= self._ping_interval:
                with self._ka_lock:
                    self._awaiting_pong = True
                    self._ping_sent_at = now
                try:
                    self._send(c.TYPE_PING, b"")
                except OSError:
                    self._trigger_loss("błąd wysyłania PING")
                    break

    # ------------------------------------------------------------------ #
    # Obsługa utraty połączenia i auto-reconnect
    # ------------------------------------------------------------------ #
    def _trigger_loss(self, reason: str) -> None:
        # Pojedyncza ścieżka utraty połączenia: wołana przez reader i keep-alive.
        if self._closing:
            return                          # rozłączenie zamierzone (close())
        with self._loss_lock:
            if self._handling_loss:
                return                      # już obsługujemy tę utratę
            self._handling_loss = True
        self._running = False
        try:
            if self._sock is not None:
                self._sock.close()          # odblokuj wątek odczytu na starym gnieździe
        except OSError:
            pass
        if self.on_disconnect:
            self.on_disconnect(self, reason)
        if self.auto_reconnect and self.username and self.session_token:
            threading.Thread(target=self._reconnect_worker, daemon=True).start()
        else:
            self._handling_loss = False

    def _reconnect_worker(self) -> None:
        for attempt in range(1, self._reconnect_max_attempts + 1):
            time.sleep(self._reconnect_backoff)
            try:
                self.reconnect()            # connect + hello + resume
                self.start()
                self._handling_loss = False
                if self.on_reconnect:
                    self.on_reconnect(self, attempt)
                return
            except (OSError, TCMPError):
                continue                    # token mógł nie być jeszcze wznawialny
        self._handling_loss = False         # wyczerpano próby - pozostajemy offline

    # ------------------------------------------------------------------ #
    # Zamknięcie
    # ------------------------------------------------------------------ #
    def close(self, *, send_bye: bool = True) -> None:
        self._closing = True   # zamierzone -> _trigger_loss nie wznawia sesji
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
