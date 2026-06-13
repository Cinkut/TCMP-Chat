"""Interaktywny klient terminalowy TCMPChat.

Uruchomienie (z katalogu tcmpchat/):
    python -m client.cli --tls --cafile tests/fixtures/ca_cert.pem
    # opcjonalnie auto-logowanie skrótem:
    python -m client.cli --user alice --password alice123 --tls --cafile ...

Model rozmowy (zgodny z dokumentacją aplikacji, UC1-UC5):
    /register <user> <hasło>   załóż konto i zaloguj się
    /login <user> <hasło>      zaloguj się
    /chat <user>               ustaw aktywnego rozmówcę
    <tekst>                     wyślij wiadomość do aktywnego rozmówcy
    /file <ścieżka>            wyślij plik graficzny do aktywnego rozmówcy
    /help                       lista komend
    /quit                       czyste zamknięcie sesji (BYE)

Odebrane pliki zapisywane są do katalogu ./downloads/.
"""
import argparse
import sys

from tcmp.errors import TCMPError

from .tcmp_client import TCMPClient

DOWNLOAD_DIR = "downloads"

_HELP = (
    "Komendy:\n"
    "  /register <user> <hasło>  załóż konto i zaloguj się\n"
    "  /login <user> <hasło>     zaloguj się\n"
    "  /chat <user>              ustaw aktywnego rozmówcę\n"
    "  <tekst>                    wyślij wiadomość do aktywnego rozmówcy\n"
    "  /file <ścieżka>           wyślij plik (JPEG/PNG) do aktywnego rozmówcy\n"
    "  /help                      ta pomoc\n"
    "  /quit                      wyjście"
)


class CLISession:
    """Stan lokalny klienta CLI: aktywny rozmówca + opcje połączenia.

    Aktywny rozmówca jest stanem wyłącznie po stronie klienta (spec §4.2,
    UC4) i przeżywa wznowienie sesji - dzięki temu po reconnect rozmowa
    wraca do tego samego odbiorcy bez akcji użytkownika.
    """

    def __init__(self, client, *, use_tls=False, cafile=None,
                 agent="TCMP-CLI/1.0", out=print):
        self.client = client
        self.use_tls = use_tls
        self.cafile = cafile
        self.agent = agent
        self.out = out
        self.active_chat = None
        self._started = False

    def ensure_connected(self) -> None:
        if self.client._sock is None:
            self.client.connect(use_tls=self.use_tls, cafile=self.cafile)
            self.client.hello(self.agent)

    def authenticate(self, user: str, password: str) -> dict:
        """Wspólna ścieżka /login i /register: HELLO -> AUTH -> AUTH_OK.

        Protokół nie rozróżnia rejestracji od logowania (spec §4.2): serwer
        zakłada konto, gdy login nie istnieje, lub weryfikuje hasło, gdy
        istnieje. Po sukcesie startuje wątek odbiorczy.
        """
        self.ensure_connected()
        ok = self.client.login(user, password)
        if not self._started:
            self.client.start()
            self._started = True
        return ok


def handle_command(session: CLISession, line: str, out=None) -> bool:
    """Przetwarza jedną linię wejścia. Zwraca False, gdy należy zakończyć.

    Wydzielone z pętli wejścia, by dało się testować bez stdin/sieci.
    """
    out = out or session.out
    client = session.client
    line = line.rstrip("\n")
    stripped = line.strip()
    if not stripped:
        return True

    # Goły tekst (bez wiodącego "/") -> wiadomość do aktywnego rozmówcy.
    if not stripped.startswith("/"):
        if client.username is None:
            out("[ERR] Najpierw zaloguj się: /login <user> <hasło>")
            return True
        if session.active_chat is None:
            out("[ERR] Nie wybrano rozmówcy. Użyj /chat <username>")
            return True
        try:
            client.send_message(session.active_chat, stripped)
            out(f"[{client.username} -> {session.active_chat}] {stripped}")
        except (OSError, RuntimeError, ValueError) as exc:
            out(f"[błąd wysyłki: {exc}]")
        return True

    parts = stripped.split(" ", 2)
    cmd = parts[0].lower()

    if cmd in ("/quit", "/q", "/exit"):
        return False
    if cmd == "/help":
        out(_HELP)
        return True

    if cmd in ("/login", "/register"):
        if len(parts) < 3:
            out(f"Składnia: {cmd} <user> <hasło>")
            return True
        user, password = parts[1], parts[2]
        if client.username is not None:
            out(f"[INFO] Jesteś już zalogowany jako {client.username}")
            return True
        try:
            ok = session.authenticate(user, password)
            out(f"[OK] Zalogowano jako {user}. "
                f"Wiadomości w kolejce: {ok['queued_messages']}.")
        except (OSError, TCMPError) as exc:
            out(f"[ERR] Logowanie nieudane: {exc}")
        return True

    # Pozostałe komendy wymagają zalogowania.
    if client.username is None:
        out("[ERR] Najpierw zaloguj się: /login <user> <hasło>")
        return True

    if cmd == "/chat":
        if len(parts) < 2:
            out("Składnia: /chat <user>")
            return True
        target = parts[1]
        if target == client.username:
            out("[ERR] Nie możesz wysyłać wiadomości do siebie")
            return True
        if target == session.active_chat:
            out(f"[INFO] Już rozmawiasz z {target}")
            return True
        session.active_chat = target
        out(f"[CHAT] Aktywna rozmowa: {target}")
        return True

    if cmd == "/file":
        if len(parts) < 2:
            out("Składnia: /file <ścieżka>")
            return True
        if session.active_chat is None:
            out("[ERR] Nie wybrano rozmówcy. Użyj /chat <username>")
            return True
        path = stripped.split(" ", 1)[1].strip()   # reszta linii = ścieżka (może mieć spacje)
        try:
            client.send_file(session.active_chat, path)
            out(f"[FILE] Wysłano plik do {session.active_chat}: {path}")
        except (OSError, RuntimeError, ValueError) as exc:
            out(f"[błąd wysyłki pliku: {exc}]")
        return True

    out(f"Nieznana komenda: {cmd}   (/help)")
    return True


# --------------------------------------------------------------------------- #
# Callbacki wypisujące zdarzenia
# --------------------------------------------------------------------------- #
def _on_message(_client, m, out=print) -> None:
    out(f"\n[{m.get('sender', '?')}]: {m['text']}")


def _save_incoming_file(_client, f, out=print, download_dir=DOWNLOAD_DIR) -> None:
    import os
    os.makedirs(download_dir, exist_ok=True)
    # Bierzemy samą nazwę pliku - ochrona przed path traversal z nazwy nadawcy.
    safe_name = os.path.basename(f["filename"]) or "plik.bin"
    dest = os.path.join(download_dir, safe_name)
    with open(dest, "wb") as fh:
        fh.write(f["data"])
    out(f"\n[{f.get('sender', '?')} wysłał plik: {dest} ({len(f['data'])} B)]")


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


def _on_verbose(_client, msg, out=print) -> None:
    out(f"[VERBOSE] {msg}")


# --------------------------------------------------------------------------- #
# Punkt wejścia
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="tcmp-cli", description="Klient TCMPChat (CLI)")
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=7000)
    p.add_argument("--user", default=None, help="auto-logowanie: login (opcjonalnie)")
    p.add_argument("--password", default=None, help="auto-logowanie: hasło (opcjonalnie)")
    p.add_argument("--tls", action="store_true", help="połącz przez TLS 1.3")
    p.add_argument("--cafile", default=None, help="certyfikat CA do weryfikacji serwera")
    p.add_argument("--agent", default="TCMP-CLI/1.0")
    p.add_argument("--auto-reconnect", action="store_true",
                   help="automatycznie wznawiaj sesję po zerwaniu połączenia")
    p.add_argument("--verbose", action="store_true",
                   help="diagnostyka połączenia/TLS/handshake ([VERBOSE])")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    client = TCMPClient(args.host, args.port, auto_reconnect=args.auto_reconnect)
    session = CLISession(client, use_tls=args.tls, cafile=args.cafile, agent=args.agent)

    client.on_message = _on_message
    client.on_file = _save_incoming_file
    client.on_ack = _on_ack
    client.on_error = _on_error
    client.on_disconnect = _on_disconnect
    client.on_reconnect = _on_reconnect
    if args.verbose:
        client.on_verbose = _on_verbose

    # --user/--password = wygodny skrót auto-logowania; inaczej /login lub /register.
    if args.user and args.password:
        try:
            ok = session.authenticate(args.user, args.password)
            print(f"Zalogowano jako {args.user}. "
                  f"Wiadomości w kolejce: {ok['queued_messages']}.")
        except (OSError, TCMPError) as exc:
            print(f"Nie udało się połączyć/zalogować: {exc}", file=sys.stderr)
            return 1
    else:
        print("Zaloguj się: /login <user> <hasło>  lub  /register <user> <hasło>")
    print(_HELP)

    try:
        for line in sys.stdin:
            if not handle_command(session, line):
                break
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
    print("Do zobaczenia.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
