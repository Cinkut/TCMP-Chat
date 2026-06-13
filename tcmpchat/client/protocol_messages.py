"""Re-eksport kodowania/dekodowania payloadów TCMP.

Funkcje payloadów żyją teraz w jednym wspólnym module ``tcmp.payloads`` (klient,
serwer i narzędzia korzystają z tego samego źródła). Ten moduł pozostaje jako
cienki alias dla zgodności z istniejącym kodem klienta i testami, które
importują ``client.protocol_messages``.
"""
from tcmp.payloads import (  # noqa: F401
    encode_hello,
    encode_auth,
    encode_auth_ok,
    decode_auth_ok,
    encode_msg,
    decode_msg,
    encode_file,
    decode_file,
    encode_ack,
    decode_ack,
    decode_err,
    encode_bye,
    decode_bye,
)

__all__ = [
    "encode_hello", "encode_auth", "encode_auth_ok", "decode_auth_ok",
    "encode_msg", "decode_msg", "encode_file", "decode_file",
    "encode_ack", "decode_ack", "decode_err", "encode_bye", "decode_bye",
]
