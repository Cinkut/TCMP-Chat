"""SessionManager - stan aktywnych sesji w pamięci.

Jedna instancja współdzielona przez wszystkie wątki ClientHandler. Dict sesji
chroniony jest pojedynczym lockiem; operacje IO na gniazdach (BYE w watchdogu)
wykonywane są POZA tym lockiem, aby uniknąć zakleszczenia z lockami zapisu
do poszczególnych gniazd.
"""

import logging
import socket
import threading
import time
from collections import deque

import tcmp

log = logging.getLogger("tcmp.session")


class MsgIdCounter:
    """Monotonicznie rosnący licznik MSG_ID per sesja (start od 1), thread-safe."""

    def __init__(self):
        self._n = 0
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            self._n += 1
            return self._n


class SessionManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, dict] = {}

    # --------------------------------------------------------- rejestr sesji
    def register_session(
        self,
        username: str,
        token: str,
        key: bytes,
        sock: socket.socket,
        send_lock: threading.Lock,
        msg_id_counter: MsgIdCounter,
        addr=None,
    ) -> None:
        entry = {
            "session_token": token,
            "session_key": key,
            "socket": sock,
            "send_lock": send_lock,
            "msg_id_counter": msg_id_counter,
            "addr": addr,
            "connected_at": time.time(),
            "last_activity": time.monotonic(),
            "msg_id_registry": set(),
            "rate_limit": deque(),
            "timed_out": False,
        }
        with self._lock:
            self._sessions[username] = entry

    def unregister_session(self, username: str) -> None:
        with self._lock:
            self._sessions.pop(username, None)

    def get_session(self, username: str) -> dict | None:
        with self._lock:
            return self._sessions.get(username)

    def is_online(self, username: str) -> bool:
        with self._lock:
            return username in self._sessions

    def get_socket(self, username: str):
        with self._lock:
            s = self._sessions.get(username)
            return s["socket"] if s else None

    # ----------------------------------------------------- reguły per ramka
    def check_duplicate(self, username: str, msg_id: int) -> bool:
        """True jeśli MSG_ID był już widziany (ERR_DUPLICATE_MSG); inaczej rejestruje."""
        with self._lock:
            s = self._sessions.get(username)
            if s is None:
                return False
            registry = s["msg_id_registry"]
            if msg_id in registry:
                return True
            registry.add(msg_id)
            return False

    def check_rate_limit(self, username: str) -> bool:
        """True jeśli przekroczono limit (20 ramek / 10 s) - ERR_RATE_LIMIT."""
        now = time.monotonic()
        with self._lock:
            s = self._sessions.get(username)
            if s is None:
                return False
            dq = s["rate_limit"]
            while dq and now - dq[0] > tcmp.RATE_LIMIT_WINDOW:
                dq.popleft()
            if len(dq) >= tcmp.RATE_LIMIT_FRAMES:
                return True
            dq.append(now)
            return False

    def update_activity(self, username: str) -> None:
        with self._lock:
            s = self._sessions.get(username)
            if s is not None:
                s["last_activity"] = time.monotonic()

    # --------------------------------------------------------------- watchdog
    def reap_idle(self, timeout: float) -> list[str]:
        """Zamyka sesje bezczynne dłużej niż ``timeout`` (BYE reason=timeout).

        Zwraca listę loginów, które zostały ubite. IO wykonywane poza lockiem.
        """
        now = time.monotonic()
        with self._lock:
            stale = [
                (u, s)
                for u, s in self._sessions.items()
                if now - s["last_activity"] > timeout and not s["timed_out"]
            ]
            for _, s in stale:
                s["timed_out"] = True

        for _, s in stale:
            try:
                msg_id = s["msg_id_counter"].next()
                frame = tcmp.build_frame(
                    tcmp.TYPE_BYE, 0, msg_id, 0,
                    bytes([tcmp.BYE_REASON_TIMEOUT]), session_key=s["session_key"],
                )
                with s["send_lock"]:
                    tcmp.send_frame(s["socket"], frame)
            except OSError:
                pass
            # Odblokowuje recv w wątku handlera -> handler posprząta sesję.
            try:
                s["socket"].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return [u for u, _ in stale]
