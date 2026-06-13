"""Interaktywny klient terminalowy TCMPChat.

Uruchomienie (z katalogu tcmpchat/):
    python -m client.cli --user alice --password alice123 \
        --tls --cafile tests/fixtures/ca_cert.pem

Komendy w trakcie sesji:
    /msg <user> <tekst>     wyślij wiadomość tekstową
    /file <user> <ścieżka>  wyślij plik graficzny (JPEG/PNG)
    /help                   lista komend
    /quit                   czyste zamknięcie sesji (BYE)

Odebrane pliki zapisywane są do katalogu ./downloads/.
"""
import argparse
import os
import sys
import threading
import time

from tcmp.errors import TCMPError

from .tcmp_client import TCMPClient

DOWNLOAD_DIR = "downloads"

_HELP = (
    "Komendy:\n"
    "  /msg <user> <tekst>     wyślij wiadomość\n"
    "  /file <user> <ścieżka>  wyślij plik (JPEG/PNG)\n"
    "  /help                   ta pomoc\n"
    "  /quit                   wyjście"
)


def handle_command(client: TCMPClient, line: str, out=print) -> bool:
    """Przetwarza jedną linię wejścia. Zwraca False, gdy należy zakończyć.

    Wydzielone z pętli wejścia, by dało się testować bez stdin/sieci.
    """
    line = line.strip()
    if not line:
        return True
    if not line.startswith("/"):
        out("Użyj komendy, np. /msg bob Cześć!   (/help)")
        return True

    parts = line.split(" ", 2)
    cmd = parts[0].lower()

    if cmd in ("/quit", "/q", "/exit"):
        return False
    if cmd == "/help":
        out(_HELP)
        return True
    if cmd == "/msg":
        if len(parts) < 3:
            out("Składnia: /msg <user> <tekst>")
            return True
        recipient, text = parts[1], parts[2]
        try:
            mid = client.send_message(recipient, text)
            out(f"[wysłano #{mid} -> {recipient}]")
        except (OSError, RuntimeError, ValueError) as exc:
            out(f"[błąd wysyłki: {exc}]")
        return True
    if cmd == "/file":
        if len(parts) < 3:
            out("Składnia: /file <user> <ścieżka>")
            return True
        recipient, path = parts[1], parts[2]
        try:
            mid = client.send_file(recipient, path)
            out(f"[wysłano plik #{mid} -> {recipient}]")
        except (OSError, RuntimeError, ValueError) as exc:
            out(f"[błąd wysyłki pliku: {exc}]")
        return True

    out(f"Nieznana komenda: {cmd}   (/help)")
    return True


# --------------------------------------------------------------------------- #
# Callbacki wypisujące zdarzenia
# --------------------------------------------------------------------------- #
def _on_message(_client, m, out=print) -> None:
    out(f"\n[{m['recipient']}] <- wiadomość: {m['text']}")


def _save_incoming_file(_client, f, out=print, download_dir=DOWNLOAD_DIR) -> None:
    os.makedirs(download_dir, exist_ok=True)
    # Bierzemy samą nazwę pliku - ochrona przed path traversal z nazwy nadawcy.
    safe_name = os.path.basename(f["filename"]) or "plik.bin"
    dest = os.path.join(download_dir, safe_name)
    with open(dest, "wb") as fh:
        fh.write(f["data"])
    out(f"\n[odebrano plik: {dest} ({len(f['data'])} B)]")


def _on_ack(_client, a, out=print) -> None:
    status = "dostarczono" if a.get("status") == 0x00 else "zakolejkowano"
    target = a.get("recipient", "?")
    out(f"[ACK #{a['ack_msg_id']} -> {target}: {status}]")


def _on_error(_client, e, out=print) -> None:
    out(f"[BŁĄD {e['name']}: {e['message']}]")


def _on_disconnect(_client, reason, out=print) -> None:
    out(f"[rozłączono: {reason}]")


def _on_reconnect(_client, attempt, out=print) -> None:
    out(f"[sesja wznowiona automatycznie (próba {attempt})]")


# --------------------------------------------------------------------------- #
# Punkt wejścia
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="tcmp-cli", description="Klient TCMPChat (CLI)")
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=7000)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--tls", action="store_true", help="połącz przez TLS 1.3")
    p.add_argument("--cafile", default=None, help="certyfikat CA do weryfikacji serwera")
    p.add_argument("--agent", default="TCMP-CLI/1.0")
    p.add_argument("--auto-reconnect", action="store_true",
                   help="automatycznie wznawiaj sesję po zerwaniu połączenia")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    client = TCMPClient(args.host, args.port, auto_reconnect=args.auto_reconnect)

    try:
        client.connect(use_tls=args.tls, cafile=args.cafile)
        client.hello(args.agent)
        ok = client.login(args.user, args.password)
    except (OSError, TCMPError) as exc:
        print(f"Nie udało się połączyć/zalogować: {exc}", file=sys.stderr)
        return 1

    client.on_message = _on_message
    client.on_file = _save_incoming_file
    client.on_ack = _on_ack
    client.on_error = _on_error
    client.on_disconnect = _on_disconnect
    client.on_reconnect = _on_reconnect
    client.start()

    print(f"Zalogowano jako {args.user}. Wiadomości w kolejce: {ok['queued_messages']}.")
    print(_HELP)

    try:
        for line in sys.stdin:
            if not handle_command(client, line):
                break
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
    print("Do zobaczenia.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
