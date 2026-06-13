"""TCMP - wspólna biblioteka protokołu Text Chat Messaging Protocol.

Re-eksportuje pełne publiczne API protokołu, dzięki czemu serwer i klient
mogą używać jednego importu: ``import tcmp`` daje dostęp do wszystkich
stałych, wyjątków i funkcji (np. ``tcmp.TYPE_MSG``, ``tcmp.build_frame``,
``tcmp.TCMPError``).
"""

from .constants import *          # noqa: F401,F403  (stałe protokołu)
from .errors import TCMPError     # noqa: F401
from .hmac_utils import (         # noqa: F401
    PRE_AUTH_TYPES, ZERO_HMAC, compute_hmac, verify_hmac, verify_frame,
)
from .frame import (              # noqa: F401
    pack_string, unpack_string, build_frame, parse_frame, validate_frame,
    recv_frame, send_frame,
)
from .fragment import (           # noqa: F401
    Fragment, MAX_FRAGMENT_PAYLOAD, fragment_payload, ReassemblyBuffer,
)
from .payloads import (           # noqa: F401  (kodowanie/dekodowanie payloadów)
    encode_hello, encode_auth, encode_auth_ok, decode_auth_ok,
    encode_msg, decode_msg, encode_file, decode_file,
    encode_ack, decode_ack, decode_err, encode_bye, decode_bye,
)
