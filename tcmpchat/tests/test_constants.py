"""Testy spójności stałych protokołu TCMP względem specyfikacji v1.0."""
import unittest

from tcmp import constants as c


class TestFrameHeaderLayout(unittest.TestCase):
    def test_header_length_is_49(self):
        self.assertEqual(c.HEADER_LENGTH, 49)

    def test_payload_offset_equals_header_length(self):
        self.assertEqual(c.OFFSET_PAYLOAD, c.HEADER_LENGTH)

    def test_field_offsets_match_spec(self):
        self.assertEqual(c.OFFSET_VER, 0x00)
        self.assertEqual(c.OFFSET_TYPE, 0x01)
        self.assertEqual(c.OFFSET_FLAGS, 0x02)
        self.assertEqual(c.OFFSET_MSG_ID, 0x03)
        self.assertEqual(c.OFFSET_LENGTH, 0x0B)
        self.assertEqual(c.OFFSET_FRAG_NUM, 0x0F)
        self.assertEqual(c.OFFSET_HMAC, 0x11)

    def test_field_sizes_sum_to_header_length(self):
        total = (c.SIZE_VER + c.SIZE_TYPE + c.SIZE_FLAGS + c.SIZE_MSG_ID
                 + c.SIZE_LENGTH + c.SIZE_FRAG_NUM + c.SIZE_HMAC)
        self.assertEqual(total, c.HEADER_LENGTH)

    def test_offsets_are_contiguous(self):
        self.assertEqual(c.OFFSET_VER + c.SIZE_VER, c.OFFSET_TYPE)
        self.assertEqual(c.OFFSET_TYPE + c.SIZE_TYPE, c.OFFSET_FLAGS)
        self.assertEqual(c.OFFSET_FLAGS + c.SIZE_FLAGS, c.OFFSET_MSG_ID)
        self.assertEqual(c.OFFSET_MSG_ID + c.SIZE_MSG_ID, c.OFFSET_LENGTH)
        self.assertEqual(c.OFFSET_LENGTH + c.SIZE_LENGTH, c.OFFSET_FRAG_NUM)
        self.assertEqual(c.OFFSET_FRAG_NUM + c.SIZE_FRAG_NUM, c.OFFSET_HMAC)
        self.assertEqual(c.OFFSET_HMAC + c.SIZE_HMAC, c.OFFSET_PAYLOAD)

    def test_hmac_size_is_sha256(self):
        self.assertEqual(c.SIZE_HMAC, 32)


class TestTransport(unittest.TestCase):
    def test_protocol_version(self):
        self.assertEqual(c.PROTOCOL_VERSION, 0x01)

    def test_default_port(self):
        self.assertEqual(c.DEFAULT_PORT, 7000)


class TestFrameTypes(unittest.TestCase):
    def test_type_values(self):
        self.assertEqual(c.TYPE_HELLO, 0x01)
        self.assertEqual(c.TYPE_AUTH, 0x02)
        self.assertEqual(c.TYPE_AUTH_OK, 0x03)
        self.assertEqual(c.TYPE_MSG, 0x04)
        self.assertEqual(c.TYPE_FILE, 0x05)
        self.assertEqual(c.TYPE_ACK, 0x06)
        self.assertEqual(c.TYPE_PING, 0x07)
        self.assertEqual(c.TYPE_PONG, 0x08)
        self.assertEqual(c.TYPE_ERR, 0x09)
        self.assertEqual(c.TYPE_BYE, 0x0A)

    def test_type_range(self):
        self.assertEqual(c.TYPE_MIN, 0x01)
        self.assertEqual(c.TYPE_MAX, 0x0A)

    def test_all_types_within_range(self):
        for code in c.TYPE_NAMES:
            self.assertTrue(c.TYPE_MIN <= code <= c.TYPE_MAX)

    def test_type_names_cover_all_codes(self):
        self.assertEqual(len(c.TYPE_NAMES), 10)
        self.assertEqual(set(c.TYPE_NAMES), set(range(c.TYPE_MIN, c.TYPE_MAX + 1)))

    def test_type_codes_unique(self):
        self.assertEqual(len(set(c.TYPE_NAMES.values())), len(c.TYPE_NAMES))


class TestFlags(unittest.TestCase):
    def test_more_data_flag(self):
        self.assertEqual(c.FLAG_MORE_DATA, 0x01)

    def test_more_data_is_bit0(self):
        # tylko bit 0 ustawiony
        self.assertEqual(c.FLAG_MORE_DATA & 0xFE, 0)


class TestErrorCodes(unittest.TestCase):
    def test_sample_values(self):
        self.assertEqual(c.ERR_UNSUPPORTED_VERSION, 0x0001)
        self.assertEqual(c.ERR_HMAC_INVALID, 0x000E)
        self.assertEqual(c.ERR_INTERNAL, 0x0010)

    def test_error_names_cover_full_range(self):
        self.assertEqual(len(c.ERR_NAMES), 16)
        self.assertEqual(set(c.ERR_NAMES), set(range(0x0001, 0x0010 + 1)))

    def test_error_codes_unique(self):
        self.assertEqual(len(set(c.ERR_NAMES.values())), len(c.ERR_NAMES))

    def test_fatal_errors_subset_of_all(self):
        self.assertTrue(c.FATAL_ERRORS.issubset(set(c.ERR_NAMES)))

    def test_known_fatal_and_nonfatal(self):
        self.assertIn(c.ERR_HMAC_INVALID, c.FATAL_ERRORS)
        self.assertIn(c.ERR_TOKEN_EXPIRED, c.FATAL_ERRORS)
        self.assertNotIn(c.ERR_RATE_LIMIT, c.FATAL_ERRORS)
        self.assertNotIn(c.ERR_UNKNOWN_RECIPIENT, c.FATAL_ERRORS)


class TestPayloadFieldValues(unittest.TestCase):
    def test_ack_status(self):
        self.assertEqual(c.ACK_STATUS_DELIVERED, 0x00)
        self.assertEqual(c.ACK_STATUS_QUEUED, 0x01)

    def test_bye_reason(self):
        self.assertEqual(c.BYE_REASON_CLEAN, 0x00)
        self.assertEqual(c.BYE_REASON_TIMEOUT, 0x01)
        self.assertEqual(c.BYE_REASON_ERROR, 0x02)

    def test_mimetype(self):
        self.assertEqual(c.MIMETYPE_JPEG, 0x01)
        self.assertEqual(c.MIMETYPE_PNG, 0x02)


class TestLimits(unittest.TestCase):
    def test_max_file_size_5mb(self):
        self.assertEqual(c.MAX_FILE_SIZE, 5 * 1024 * 1024)

    def test_max_text_fragment_fits_2byte_field(self):
        self.assertEqual(c.MAX_TEXT_PER_FRAGMENT, 0xFFFF)

    def test_session_key_length(self):
        self.assertEqual(c.SESSION_KEY_LENGTH, 32)


if __name__ == "__main__":
    unittest.main()
