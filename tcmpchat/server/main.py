"""Punkt wejścia serwera TCMPChat (tcmpchat-server).

Uruchomienie (z katalogu tcmpchat/):
    python -m server.main --cert cert.pem --key key.pem [--db users.db]
"""

import argparse
import logging
import os
import sys

# Pozwala uruchomić serwer niezależnie od bieżącego katalogu - dokłada
# katalog tcmpchat/ do sys.path, dzięki czemu `import tcmp` działa.
_TCMPCHAT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _TCMPCHAT_DIR not in sys.path:
    sys.path.insert(0, _TCMPCHAT_DIR)

from server.auth import AuthModule          # noqa: E402
from server.database import DatabaseLayer    # noqa: E402
from server.server import TCMPServer         # noqa: E402
from server.session import SessionManager    # noqa: E402


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="tcmpchat-server", description="Serwer TCMPChat")
    parser.add_argument("--host", default="0.0.0.0", help="adres nasłuchu (domyślnie 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7000, help="port TCP (domyślnie 7000)")
    parser.add_argument("--cert", required=True, help="ścieżka do certyfikatu TLS (PEM)")
    parser.add_argument("--key", required=True, help="ścieżka do klucza prywatnego TLS (PEM)")
    parser.add_argument("--db", default="users.db", help="ścieżka do bazy SQLite (domyślnie users.db)")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO"], help="poziom logowania"
    )
    parser.add_argument(
        "--log-file", default="tcmpchat-server.log",
        help="plik logów zapisywany równolegle ze stdout (pusty = tylko stdout)",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    # Logi jednocześnie na stdout i (opcjonalnie) do pliku - spec §5.5.
    fmt = logging.Formatter(
        "[%(levelname)s] %(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
    logging.basicConfig(level=getattr(logging, args.log_level), handlers=handlers)
    log = logging.getLogger("tcmp.main")

    for path, label in ((args.cert, "certyfikat"), (args.key, "klucz")):
        if not os.path.isfile(path):
            log.error("Nie znaleziono pliku (%s): %s", label, path)
            return 1

    db = DatabaseLayer(args.db)
    db.init_schema()
    removed = db.cleanup_expired_sessions()
    if removed:
        log.info("usunięto %d wygasłych sesji przy starcie", removed)

    auth = AuthModule(db)
    session_manager = SessionManager()
    server = TCMPServer(args.host, args.port, args.cert, args.key, db, auth, session_manager)

    try:
        server.start()
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
