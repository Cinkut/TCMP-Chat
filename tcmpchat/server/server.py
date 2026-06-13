"""TCMPServer - pętla nasłuchu TLS 1.3 + wątek watchdog timeoutów.

Model thread-per-client: każde połączenie obsługiwane jest w osobnym wątku
ClientHandler. Połączenia bez aktywnego TLS odrzucane są natychmiast.
"""

import logging
import socket
import ssl
import threading
import time

import tcmp
from server.handler import ClientHandler

log = logging.getLogger("tcmp.server")

WATCHDOG_INTERVAL = 15   # co ile sekund sprawdzać bezczynne sesje
LISTEN_BACKLOG = 50


class TCMPServer:
    def __init__(self, host, port, certfile, keyfile, db, auth, session_manager):
        self.host = host
        self.port = port
        self.db = db
        self.auth = auth
        self.session_manager = session_manager

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile, keyfile)
        self.ssl_context = ctx

    # --------------------------------------------------------------- watchdog
    def _watchdog(self) -> None:
        while True:
            time.sleep(WATCHDOG_INTERVAL)
            try:
                reaped = self.session_manager.reap_idle(tcmp.TIMEOUT_IDLE)
                for username in reaped:
                    log.info("sesja zamknięta (timeout bezczynności): %s", username)
            except Exception:
                log.exception("błąd watchdoga")

    # ------------------------------------------------------------------ start
    def start(self) -> None:
        threading.Thread(target=self._watchdog, daemon=True, name="watchdog").start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(LISTEN_BACKLOG)
        log.info("TCMPServer nasłuchuje na %s:%d (TLS 1.3)", self.host, self.port)

        try:
            while True:
                conn, addr = srv.accept()
                try:
                    ssl_conn = self.ssl_context.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    log.warning("odrzucono połączenie %s (TLS handshake: %s)", addr, exc)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                handler = ClientHandler(
                    ssl_conn, addr, self.db, self.auth, self.session_manager
                )
                threading.Thread(target=handler.run, daemon=True).start()
        except KeyboardInterrupt:
            log.info("zatrzymywanie serwera (Ctrl+C)")
        finally:
            srv.close()
