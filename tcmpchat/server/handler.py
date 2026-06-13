"""ClientHandler - osobny wątek per klient, maszyna stanów protokołu TCMP.

Przebieg: CONNECTED -> HELLO_RECEIVED -> AUTHENTICATED -> DELIVERING_QUEUE
-> MESSAGING -> CLOSING. Reguły walidacji ramki delegowane są do pakietu
``tcmp`` (parse/validate/HMAC); tu znajduje się logika sesji, routing i kolejka.

Nigdy nie logujemy treści wiadomości - tylko metadane (typ, MSG_ID, LENGTH).
"""

import logging
import socket
import struct
import threading
import time

import tcmp
from server.auth import AuthFailedError
from server.session import MsgIdCounter

log = logging.getLogger("tcmp.handler")

SOCK_TIMEOUT = 10.0   # timeout pojedynczego recv (wykrywanie niekompletnych ramek)


class _SilentClose(Exception):
    """Zamknięcie połączenia bez wysyłania ramki TCMP (np. timeout HELLO)."""


class _AuthLimitError(Exception):
    """Przekroczono limit prób AUTH - ERR/BYE już wysłane."""


def _now_ms() -> int:
    return int(time.time() * 1000)


class ClientHandler:
    def __init__(self, sock, addr, db, auth, session_manager):
        self.sock = sock
        self.addr = addr
        self.db = db
        self.auth = auth
        self.session_manager = session_manager

        self.username: str | None = None
        self.session_token: str | None = None
        self.session_key: bytes | None = None

        self._send_lock = threading.Lock()        # serializuje zapisy do TEGO gniazda
        self._counter = MsgIdCounter()             # MSG_ID serwera per sesja
        self._reasm = tcmp.ReassemblyBuffer()      # osobny bufor per handler

        self._clean_close = False                  # klient wysłał BYE(clean)
        self._fatal = False                        # zamknięcie z powodu błędu fatalnego

    # ===================================================================== run
    def run(self) -> None:
        log.info("klient połączony %s", self._addr_str())
        try:
            self.sock.settimeout(SOCK_TIMEOUT)
            self.handle_connected()
            self.handle_hello()
            self.handle_messaging()
        except _SilentClose:
            pass
        except _AuthLimitError:
            pass
        except tcmp.TCMPError as exc:
            self._report_protocol_error(exc)
        except (ConnectionError, OSError):
            log.info("klient rozłączony (nagłe zerwanie) %s", self._addr_str())
        except Exception:
            log.exception("nieoczekiwany błąd w sesji %s", self._addr_str())
            self._fatal = True
            self._safe_send(self.send_err, tcmp.ERR_INTERNAL, "Internal server error")
        finally:
            self.cleanup()

    # ====================================================== faza 1: CONNECTED
    def handle_connected(self) -> None:
        try:
            parsed, _ = self._recv_phase(tcmp.TIMEOUT_HELLO)
        except socket.timeout:
            log.info("timeout oczekiwania na HELLO %s", self._addr_str())
            raise _SilentClose
        if parsed["type"] != tcmp.TYPE_HELLO:
            raise tcmp.TCMPError(tcmp.ERR_UNKNOWN_TYPE, "oczekiwano HELLO")
        self._validate_hello(parsed["payload"])

    def _validate_hello(self, payload: bytes) -> None:
        try:
            version = payload[0]
            agent, _ = tcmp.unpack_string(payload, 1)
        except (IndexError, struct.error):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, "HELLO payload")
        except UnicodeDecodeError:
            raise tcmp.TCMPError(tcmp.ERR_INVALID_ENCODING, "client_agent")
        if version != tcmp.PROTOCOL_VERSION:
            raise tcmp.TCMPError(tcmp.ERR_UNSUPPORTED_VERSION, f"HELLO ver=0x{version:02X}")
        log.debug("HELLO od %s agent=%r", self._addr_str(), agent[:64])

    # =========================================================== faza 2: AUTH
    def handle_hello(self) -> None:
        attempts = 0
        try:
            while attempts < tcmp.AUTH_MAX_ATTEMPTS:
                parsed, _ = self._recv_phase(tcmp.TIMEOUT_AUTH)
                if parsed["type"] != tcmp.TYPE_AUTH:
                    raise tcmp.TCMPError(tcmp.ERR_UNKNOWN_TYPE, "oczekiwano AUTH")
                username, password, resume_token = self._parse_auth(parsed["payload"])
                try:
                    token, key = self._authenticate(username, password, resume_token)
                except AuthFailedError as exc:
                    attempts += 1
                    log.info("AUTH nieudany (%s) próba %d/%d",
                             username, attempts, tcmp.AUTH_MAX_ATTEMPTS)
                    self.send_err(tcmp.ERR_AUTH_FAILED, str(exc))
                    continue
                self._on_authenticated(username, token, key)
                return
        except socket.timeout:
            log.info("timeout oczekiwania na AUTH %s", self._addr_str())
            self._safe_send(self.send_bye, tcmp.BYE_REASON_TIMEOUT)
            raise _SilentClose

        # Wyczerpano próby (3x AUTH_FAILED).
        self.send_err(tcmp.ERR_AUTH_LIMIT, "Max attempts reached")
        self.send_bye(tcmp.BYE_REASON_ERROR)
        log.info("limit prób AUTH przekroczony %s", self._addr_str())
        raise _AuthLimitError

    def _authenticate(self, username, password, resume_token) -> tuple[str, bytes]:
        if resume_token:
            return self.auth.resume(username, resume_token)
        if self.db.get_user(username):
            return self.auth.login(username, password)
        return self.auth.register(username, password)

    def _on_authenticated(self, username, token, key) -> None:
        self.username = username
        self.session_token = token
        self.session_key = key
        self.session_manager.register_session(
            username, token, key, self.sock, self._send_lock, self._counter, self.addr
        )
        queued = self.db.get_queued_messages(username)
        self.send_auth_ok(token, key, len(queued))
        log.info("AUTH OK (%s) kolejka=%d", username, len(queued))
        self.deliver_queue(queued)

    @staticmethod
    def _parse_auth(payload: bytes):
        try:
            username, off = tcmp.unpack_string(payload, 0)
            (pw_len,) = struct.unpack_from("!H", payload, off)
            off += 2
            password = payload[off:off + pw_len].decode("utf-8")
            off += pw_len
            resume_token = None
            if off + 2 <= len(payload):
                (rt_len,) = struct.unpack_from("!H", payload, off)
                off += 2
                if rt_len > 0:
                    resume_token = payload[off:off + rt_len].decode("utf-8")
        except (IndexError, struct.error):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, "AUTH payload")
        except UnicodeDecodeError:
            raise tcmp.TCMPError(tcmp.ERR_INVALID_ENCODING, "AUTH field")
        return username, password, resume_token

    # =============================================== faza 3: DELIVERING_QUEUE
    def deliver_queue(self, messages: list[dict]) -> None:
        for msg in messages:
            msg_id = self._send_payload(msg["type"], msg["payload"])
            try:
                parsed, _ = self._recv_frame()
            except socket.timeout:
                log.info("brak ACK w fazie kolejki (%s) - reszta zostaje zakolejkowana",
                         self.username)
                return
            if parsed["type"] == tcmp.TYPE_ACK and self._ack_msg_id(parsed["payload"]) == msg_id:
                self.db.mark_delivered(msg["id"])
        if messages:
            log.info("dostarczono kolejkę (%s)", self.username)

    # ===================================================== faza 4: MESSAGING
    def handle_messaging(self) -> None:
        while not self._clean_close:
            try:
                parsed, raw = self._recv_frame()
            except socket.timeout:
                continue   # bezczynność - twardy limit egzekwuje watchdog
            except tcmp.TCMPError as exc:
                self._report_protocol_error(exc)
                if exc.fatal:
                    raise
                continue
            self.session_manager.update_activity(self.username)
            try:
                self._dispatch(parsed, raw)
            except tcmp.TCMPError as exc:
                self._report_protocol_error(exc)
                if exc.fatal:
                    raise

    def _dispatch(self, parsed: dict, raw: bytes) -> None:
        t = parsed["type"]
        if t == tcmp.TYPE_MSG:
            self.handle_data_frame(parsed, tcmp.TYPE_MSG)
        elif t == tcmp.TYPE_FILE:
            self.handle_data_frame(parsed, tcmp.TYPE_FILE)
        elif t == tcmp.TYPE_PING:
            self.send_pong()
        elif t == tcmp.TYPE_ACK:
            pass   # ACK odbiorcy dla przekazanej ramki - potwierdzenie, ignorujemy
        elif t == tcmp.TYPE_BYE:
            self.handle_bye(parsed)
        else:
            raise tcmp.TCMPError(tcmp.ERR_UNKNOWN_TYPE, f"nieobsługiwany typ 0x{t:02X}")

    def handle_data_frame(self, parsed: dict, type_: int) -> None:
        if self.session_manager.check_rate_limit(self.username):
            raise tcmp.TCMPError(tcmp.ERR_RATE_LIMIT, "Rate limit exceeded")
        # Duplikat sprawdzamy tylko na pierwszym fragmencie - wszystkie fragmenty
        # jednej wiadomości dzielą MSG_ID.
        if parsed["frag_num"] == 0 and self.session_manager.check_duplicate(
            self.username, parsed["msg_id"]
        ):
            raise tcmp.TCMPError(tcmp.ERR_DUPLICATE_MSG, "Duplicate MSG_ID")

        try:
            assembled = self._reasm.receive(
                parsed["msg_id"], parsed["frag_num"], parsed["more_data"], parsed["payload"]
            )
        except tcmp.TCMPError:
            self._reasm.discard(parsed["msg_id"])
            raise

        if assembled is None:
            # Fragment pośredni - potwierdź i czekaj na kolejny.
            self.send_ack(parsed["msg_id"], tcmp.ACK_STATUS_DELIVERED)
            return

        # Nadpisz `sender` uwierzytelnioną nazwą - nie ufamy wartości od klienta
        # (anti-spoofing). Zapisana i przekazana ramka niesie autorytatywnego nadawcę.
        assembled = self._restamp_sender(assembled, self.username)
        _, recipient, timestamp = self._parse_envelope(assembled)
        if type_ == tcmp.TYPE_FILE:
            self._validate_file(assembled)

        if not self.db.get_user(recipient):
            raise tcmp.TCMPError(tcmp.ERR_UNKNOWN_RECIPIENT, f"User {recipient} not found")

        delivered = self.session_manager.is_online(recipient) and self.forward_to_recipient(
            recipient, type_, assembled
        )
        message_id = self.db.save_message(
            self.username, recipient, type_, assembled, timestamp
        )
        if delivered:
            self.db.mark_delivered(message_id)
            self.send_ack(parsed["msg_id"], tcmp.ACK_STATUS_DELIVERED)
            log.info("MSG routed %s -> %s (delivered)", self.username, recipient)
        else:
            self.send_ack(parsed["msg_id"], tcmp.ACK_STATUS_QUEUED)
            log.info("MSG routed %s -> %s (queued)", self.username, recipient)

    def forward_to_recipient(self, recipient: str, type_: int, payload: bytes) -> bool:
        session = self.session_manager.get_session(recipient)
        if session is None:
            return False
        try:
            self._send_payload(type_, payload, session=session)
            return True
        except OSError:
            return False   # odbiorca rozłączył się w międzyczasie -> zakolejkuj

    def handle_bye(self, parsed: dict) -> None:
        reason = parsed["payload"][0] if parsed["payload"] else tcmp.BYE_REASON_CLEAN
        self._clean_close = True
        self._safe_send(self.send_bye, tcmp.BYE_REASON_CLEAN)
        log.info("klient rozłączony (BYE reason=0x%02X) %s", reason, self.username or self._addr_str())

    # ============================================================== payloady
    @staticmethod
    def _restamp_sender(payload: bytes, sender: str) -> bytes:
        """Nadpisuje pole `sender` (pierwsze pole MSG/FILE) uwierzytelnioną nazwą.

        Klient mógł wstawić dowolną wartość - serwer ustawia ją autorytatywnie,
        aby uniemożliwić podszywanie się pod innego nadawcę.
        """
        try:
            _, off = tcmp.unpack_string(payload, 0)
        except (IndexError, struct.error):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, "brak pola sender")
        except UnicodeDecodeError:
            raise tcmp.TCMPError(tcmp.ERR_INVALID_ENCODING, "sender")
        return tcmp.pack_string(sender) + payload[off:]

    @staticmethod
    def _parse_envelope(payload: bytes) -> tuple[str, str, int]:
        """Wspólny początek payloadu MSG/FILE: sender + recipient + timestamp (8B)."""
        try:
            sender, off = tcmp.unpack_string(payload, 0)
            recipient, off = tcmp.unpack_string(payload, off)
            (timestamp,) = struct.unpack_from("!Q", payload, off)
        except (IndexError, struct.error):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, "envelope")
        except UnicodeDecodeError:
            raise tcmp.TCMPError(tcmp.ERR_INVALID_ENCODING, "sender/recipient")
        return sender, recipient, timestamp

    @staticmethod
    def _validate_file(payload: bytes) -> None:
        # sender(str) + recipient(str) + timestamp(8) + filename(str)
        # + mimetype_id(1) + total_filesize(4) + ...
        try:
            _, off = tcmp.unpack_string(payload, 0)     # sender
            _, off = tcmp.unpack_string(payload, off)   # recipient
            off += 8                                     # timestamp
            _, off = tcmp.unpack_string(payload, off)   # filename
            mimetype_id = payload[off]
            off += 1
            (total_filesize,) = struct.unpack_from("!I", payload, off)
        except (IndexError, struct.error):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, "FILE payload")
        except UnicodeDecodeError:
            raise tcmp.TCMPError(tcmp.ERR_INVALID_ENCODING, "filename")
        if mimetype_id not in (tcmp.MIMETYPE_JPEG, tcmp.MIMETYPE_PNG):
            raise tcmp.TCMPError(tcmp.ERR_MALFORMED_PAYLOAD, f"mimetype_id=0x{mimetype_id:02X}")
        if total_filesize > tcmp.MAX_FILE_SIZE:
            raise tcmp.TCMPError(tcmp.ERR_FILE_TOO_LARGE, f"total_filesize={total_filesize}")

    @staticmethod
    def _ack_msg_id(payload: bytes) -> int:
        (ack_id,) = struct.unpack_from("!Q", payload, 0)
        return ack_id

    # =============================================================== wysyłka
    def _send_payload(self, type_: int, payload: bytes, session: dict | None = None) -> int:
        """Wysyła payload jako jedną lub wiele ramek (fragmentacja > 65 535B).

        Wszystkie fragmenty dzielą jeden MSG_ID; flaga MORE_DATA na wszystkich
        oprócz ostatniego. ``session=None`` -> wysyłka do własnego gniazda;
        inaczej do gniazda wskazanej sesji (przekazanie do odbiorcy).
        """
        if session is None:
            counter, lock, sock, key = self._counter, self._send_lock, self.sock, self.session_key
        else:
            counter = session["msg_id_counter"]
            lock = session["send_lock"]
            sock = session["socket"]
            key = session["session_key"]

        msg_id = counter.next()
        fragments = tcmp.fragment_payload(payload)
        with lock:
            for frag in fragments:
                flags = tcmp.FLAG_MORE_DATA if frag.more_data else 0
                frame = tcmp.build_frame(type_, flags, msg_id, frag.frag_num, frag.data, session_key=key)
                tcmp.send_frame(sock, frame)
        return msg_id

    def _send(self, type_: int, payload: bytes) -> int:
        msg_id = self._counter.next()
        frame = tcmp.build_frame(type_, 0, msg_id, 0, payload, session_key=self.session_key)
        with self._send_lock:
            tcmp.send_frame(self.sock, frame)
        return msg_id

    def send_auth_ok(self, token: str, key: bytes, queued_count: int) -> None:
        payload = (
            tcmp.pack_string(token)
            + struct.pack("!H", len(key)) + key
            + struct.pack("!I", queued_count)
        )
        self._send(tcmp.TYPE_AUTH_OK, payload)

    def send_err(self, code: int, message: str) -> None:
        payload = struct.pack("!H", code) + tcmp.pack_string(message)
        self._send(tcmp.TYPE_ERR, payload)

    def send_bye(self, reason: int) -> None:
        self._send(tcmp.TYPE_BYE, bytes([reason]))

    def send_ack(self, ack_msg_id: int, status: int) -> None:
        payload = struct.pack("!QB", ack_msg_id, status)
        self._send(tcmp.TYPE_ACK, payload)

    def send_pong(self) -> None:
        self._send(tcmp.TYPE_PONG, b"")

    # =============================================================== odbiór
    def _recv_frame(self) -> tuple[dict, bytes]:
        """Odbiera, parsuje i waliduje ramkę (z weryfikacją HMAC gdy mamy klucz)."""
        raw = tcmp.recv_frame(self.sock)
        parsed = tcmp.parse_frame(raw)
        tcmp.validate_frame(parsed, frame_bytes=raw, session_key=self.session_key)
        log.debug("RX type=%s msg_id=%d len=%d",
                  tcmp.TYPE_NAMES.get(parsed["type"], hex(parsed["type"])),
                  parsed["msg_id"], parsed["length"])
        return parsed, raw

    def _recv_phase(self, overall_timeout: float) -> tuple[dict, bytes]:
        """recv z limitem fazy: pętla po 10s recv aż do ramki lub przekroczenia okna."""
        deadline = time.monotonic() + overall_timeout
        while True:
            try:
                return self._recv_frame()
            except socket.timeout:
                if time.monotonic() >= deadline:
                    raise
                continue

    # =============================================================== sprzątanie
    def _report_protocol_error(self, exc: tcmp.TCMPError) -> None:
        log.info("błąd protokołu %s (%s): %s",
                 tcmp.ERR_NAMES.get(exc.error_code, hex(exc.error_code)),
                 self.username or self._addr_str(), exc)
        self._safe_send(self.send_err, exc.error_code, str(exc))
        if exc.fatal:
            self._fatal = True
            self._safe_send(self.send_bye, tcmp.BYE_REASON_ERROR)

    def cleanup(self) -> None:
        if self.username is not None:
            session = self.session_manager.get_session(self.username)
            # Unregister tylko jeśli rejestr wskazuje wciąż NA TĘ sesję
            # (nie kasujemy sesji wznowionej w innym wątku).
            if session and session.get("session_token") == self.session_token:
                self.session_manager.unregister_session(self.username)

        if self.session_token is not None:
            if self._clean_close or self._fatal:
                self.db.invalidate_session(self.session_token)
            else:
                # Nagłe zerwanie / timeout: token ważny jeszcze 5 min (session resume).
                self.db.set_resume_expiry(
                    self.session_token, int(time.time()) + tcmp.SESSION_RESUME_WINDOW
                )
        try:
            self.sock.close()
        except OSError:
            pass

    # =============================================================== narzędzia
    @staticmethod
    def _safe_send(fn, *args) -> None:
        try:
            fn(*args)
        except OSError:
            pass

    def _addr_str(self) -> str:
        try:
            return f"{self.addr[0]}:{self.addr[1]}"
        except (TypeError, IndexError):
            return str(self.addr)
