"""Testy parsera komend CLI (model aktywnej rozmowy) i zapisu plików - bez sieci."""
import os
import tempfile
import unittest

from client import cli


class _FakeClient:
    """Minimalny klient: udaje nawiązane połączenie i zalogowanie."""

    def __init__(self, username="tester"):
        self.username = username
        self._sock = object()      # niepuste -> ensure_connected() nie łączy
        self.sent = []
        self.files = []

    def send_message(self, recipient, text):
        self.sent.append((recipient, text))
        return 1

    def send_file(self, recipient, path):
        self.files.append((recipient, path))
        return 2


class _Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s):
        self.lines.append(s)


class TestHandleCommand(unittest.TestCase):
    def setUp(self):
        self.client = _FakeClient()
        self.session = cli.CLISession(self.client)
        self.out = _Out()

    def _run(self, line):
        return cli.handle_command(self.session, line, out=self.out)

    def _has(self, needle):
        return any(needle in l for l in self.out.lines)

    # --- sterowanie pętlą ---------------------------------------------------
    def test_quit_returns_false(self):
        self.assertFalse(self._run("/quit"))
        self.assertFalse(self._run("/q"))

    def test_empty_line_continues_no_send(self):
        self.assertTrue(self._run("   "))
        self.assertEqual(self.client.sent, [])

    def test_help_lists_chat(self):
        self._run("/help")
        self.assertTrue(self._has("/chat"))

    # --- wybór rozmówcy (UC4) ----------------------------------------------
    def test_chat_sets_active(self):
        self.assertTrue(self._run("/chat bob"))
        self.assertEqual(self.session.active_chat, "bob")
        self.assertTrue(self._has("Aktywna rozmowa"))

    def test_chat_self_blocked(self):
        self._run("/chat tester")
        self.assertIsNone(self.session.active_chat)
        self.assertTrue(self._has("do siebie"))

    def test_chat_already_talking(self):
        self._run("/chat bob")
        self._run("/chat bob")
        self.assertTrue(self._has("Już rozmawiasz"))

    def test_chat_missing_arg(self):
        self._run("/chat")
        self.assertTrue(self._has("Składnia"))

    # --- wysyłanie wiadomości gołym tekstem --------------------------------
    def test_bare_text_requires_active(self):
        self.assertTrue(self._run("Cześć Bob!"))
        self.assertEqual(self.client.sent, [])
        self.assertTrue(self._has("Nie wybrano rozmówcy"))

    def test_bare_text_sends_to_active(self):
        self._run("/chat bob")
        self._run("to jest dłuższy tekst")
        self.assertEqual(self.client.sent, [("bob", "to jest dłuższy tekst")])

    def test_bare_text_echo_shows_sender_and_recipient(self):
        self._run("/chat bob")
        self._run("Cześć Bob!")
        self.assertTrue(any(
            "tester" in l and "bob" in l and "Cześć Bob!" in l
            for l in self.out.lines
        ))

    def test_send_error_is_caught(self):
        def boom(*_):
            raise RuntimeError("nie zalogowano")
        self.client.send_message = boom
        self._run("/chat bob")
        self.assertTrue(self._run("hej"))          # nie wyrzuca wyjątku
        self.assertTrue(self._has("błąd"))

    # --- pliki --------------------------------------------------------------
    def test_file_requires_active(self):
        self._run("/file /tmp/foto.png")
        self.assertEqual(self.client.files, [])
        self.assertTrue(self._has("Nie wybrano rozmówcy"))

    def test_file_sends_to_active(self):
        self._run("/chat alice")
        self._run("/file /tmp/foto.png")
        self.assertEqual(self.client.files, [("alice", "/tmp/foto.png")])

    # --- wymóg zalogowania --------------------------------------------------
    def test_chat_requires_login(self):
        self.client.username = None
        self._run("/chat bob")
        self.assertTrue(self._has("zaloguj"))

    def test_bare_text_requires_login(self):
        self.client.username = None
        self._run("hej")
        self.assertEqual(self.client.sent, [])
        self.assertTrue(self._has("zaloguj"))

    # --- pozostałe ----------------------------------------------------------
    def test_unknown_command(self):
        self._run("/foo bar")
        self.assertTrue(self._has("Nieznana"))


class TestSaveIncomingFile(unittest.TestCase):
    def test_saves_to_download_dir(self):
        out = _Out()
        data = b"\x89PNG\r\n" + bytes(range(64))
        with tempfile.TemporaryDirectory() as tmp:
            cli._save_incoming_file(
                None, {"filename": "obraz.png", "data": data, "sender": "bob"},
                out=out, download_dir=tmp,
            )
            dest = os.path.join(tmp, "obraz.png")
            self.assertTrue(os.path.isfile(dest))
            with open(dest, "rb") as fh:
                self.assertEqual(fh.read(), data)

    def test_strips_path_from_filename(self):
        out = _Out()
        with tempfile.TemporaryDirectory() as tmp:
            cli._save_incoming_file(
                None, {"filename": "../../evil.png", "data": b"x"},
                out=out, download_dir=tmp,
            )
            # Zapis tylko do download_dir, bez wyjścia poza katalog.
            self.assertTrue(os.path.isfile(os.path.join(tmp, "evil.png")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "..", "evil.png")))


if __name__ == "__main__":
    unittest.main()
