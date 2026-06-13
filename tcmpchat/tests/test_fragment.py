"""Testy fragmentacji i ponownego składania payloadów."""
import unittest

from tcmp import fragment as fr


class TestFragmentPayload(unittest.TestCase):
    def test_empty_payload_single_fragment(self):
        frags = fr.fragment_payload(b"")
        self.assertEqual(len(frags), 1)
        self.assertEqual(frags[0].frag_num, 0)
        self.assertFalse(frags[0].more_data)
        self.assertEqual(frags[0].data, b"")

    def test_small_payload_single_fragment(self):
        frags = fr.fragment_payload(b"hello")
        self.assertEqual(len(frags), 1)
        self.assertFalse(frags[0].more_data)
        self.assertEqual(frags[0].data, b"hello")

    def test_exact_boundary_single_fragment(self):
        data = b"x" * 4
        frags = fr.fragment_payload(data, max_chunk=4)
        self.assertEqual(len(frags), 1)
        self.assertFalse(frags[0].more_data)

    def test_splits_into_multiple(self):
        data = b"x" * 10
        frags = fr.fragment_payload(data, max_chunk=4)
        self.assertEqual(len(frags), 3)          # 4 + 4 + 2
        self.assertEqual([f.frag_num for f in frags], [0, 1, 2])
        self.assertEqual([f.more_data for f in frags], [True, True, False])
        self.assertEqual(b"".join(f.data for f in frags), data)

    def test_frag_nums_are_sequential(self):
        frags = fr.fragment_payload(b"a" * 100, max_chunk=10)
        self.assertEqual([f.frag_num for f in frags], list(range(10)))

    def test_only_last_has_no_more_data(self):
        frags = fr.fragment_payload(b"a" * 25, max_chunk=10)
        self.assertTrue(all(f.more_data for f in frags[:-1]))
        self.assertFalse(frags[-1].more_data)


class TestReassembly(unittest.TestCase):
    def test_single_fragment_message(self):
        buf = fr.ReassemblyBuffer()
        result = buf.receive(msg_id=1, frag_num=0, more_data=False, data=b"hello")
        self.assertEqual(result, b"hello")

    def test_multi_fragment_message(self):
        buf = fr.ReassemblyBuffer()
        self.assertIsNone(buf.receive(1, 0, True, b"aaa"))
        self.assertIsNone(buf.receive(1, 1, True, b"bbb"))
        result = buf.receive(1, 2, False, b"ccc")
        self.assertEqual(result, b"aaabbbccc")

    def test_roundtrip_fragment_then_reassemble(self):
        original = b"y" * 95
        frags = fr.fragment_payload(original, max_chunk=10)
        buf = fr.ReassemblyBuffer()
        result = None
        for frag in frags:
            result = buf.receive(1, frag.frag_num, frag.more_data, frag.data)
        self.assertEqual(result, original)

    def test_interleaved_messages(self):
        buf = fr.ReassemblyBuffer()
        self.assertIsNone(buf.receive(1, 0, True, b"a1"))
        self.assertIsNone(buf.receive(2, 0, True, b"b1"))
        self.assertEqual(buf.receive(1, 1, False, b"a2"), b"a1a2")
        self.assertEqual(buf.receive(2, 1, False, b"b2"), b"b1b2")

    def test_new_message_must_start_at_zero(self):
        buf = fr.ReassemblyBuffer()
        with self.assertRaises(ValueError):
            buf.receive(1, 1, True, b"oops")

    def test_out_of_order_fragment_raises(self):
        buf = fr.ReassemblyBuffer()
        buf.receive(1, 0, True, b"a")
        with self.assertRaises(ValueError):
            buf.receive(1, 2, True, b"skip")   # oczekiwano frag_num=1

    def test_discard_removes_partial(self):
        buf = fr.ReassemblyBuffer()
        buf.receive(1, 0, True, b"partial")
        buf.discard(1)
        # po discard nowa wiadomość 1 musi znów zacząć od 0
        result = buf.receive(1, 0, False, b"fresh")
        self.assertEqual(result, b"fresh")

    def test_timeout_discards_stale(self):
        buf = fr.ReassemblyBuffer(timeout=0)   # natychmiastowy timeout
        buf.receive(1, 0, True, b"a")
        expired = buf.check_timeouts()
        self.assertIn(1, expired)


if __name__ == "__main__":
    unittest.main()
