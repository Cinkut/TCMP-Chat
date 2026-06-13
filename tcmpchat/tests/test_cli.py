"""Testy parsera komend CLI i zapisu odebranych plików (bez sieci)."""
import os
import tempfile
import unittest

from client import cli


class _FakeClient:
    def __init__(self):
        self.username = "tester"   # prawdziwy klient ma username po login()
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
        self.cli = _FakeClient()
        self.out = _Out()

    def _run(self, line):
        return cli.handle_command(self.cli, line, out=self.out)

    def test_quit_returns_false(self):
        self.assertFalse(self._run("/quit"))
        self.assertFalse(self._run("/q"))

    def test_empty_line_continues_no_send(self):
        self.assertTrue(self._run("   "))
        self.assertEqual(self.cli.sent, [])

    def test_msg_sends(self):
        self.assertTrue(self._run("/msg bob Cześć Bob!"))
        self.assertEqual(self.cli.sent, [("bob", "Cześć Bob!")])

    def test_msg_echo_logs_sender_and_text(self):
        self._run("/msg bob Cześć Bob!")
        # echo lokalne musi pokazać nadawcę, odbiorcę i treść
        self.assertTrue(any(
            "tester" in l and "bob" in l and "Cześć Bob!" in l
            for l in self.out.lines
        ))

    def test_msg_preserves_spaces_in_text(self):
        self._run("/msg bob to jest dłuższy tekst")
        self.assertEqual(self.cli.sent[0], ("bob", "to jest dłuższy tekst"))

    def test_msg_missing_args(self):
        self.assertTrue(self._run("/msg bob"))
        self.assertEqual(self.cli.sent, [])
        self.assertTrue(any("Składnia" in l for l in self.out.lines))

    def test_file_sends(self):
        self._run("/file alice /tmp/foto.png")
        self.assertEqual(self.cli.files, [("alice", "/tmp/foto.png")])

    def test_plain_text_hint(self):
        self._run("po prostu tekst")
        self.assertEqual(self.cli.sent, [])
        self.assertTrue(any("/help" in l for l in self.out.lines))

    def test_unknown_command(self):
        self._run("/foo bar")
        self.assertTrue(any("Nieznana" in l for l in self.out.lines))

    def test_help(self):
        self._run("/help")
        self.assertTrue(any("/msg" in l for l in self.out.lines))

    def test_send_error_is_caught(self):
        def boom(*_):
            raise RuntimeError("nie zalogowano")
        self.cli.send_message = boom
        self.assertTrue(self._run("/msg bob hej"))   # nie wyrzuca wyjątku
        self.assertTrue(any("błąd" in l.lower() for l in self.out.lines))


class TestSaveIncomingFile(unittest.TestCase):
    def test_saves_to_download_dir(self):
        out = _Out()
        data = b"\x89PNG\r\n" + bytes(range(64))
        with tempfile.TemporaryDirectory() as tmp:
            cli._save_incoming_file(
                None, {"filename": "obraz.png", "data": data},
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
