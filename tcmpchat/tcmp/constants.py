"""
TCMP (Text Chat Messaging Protocol) - stałe protokołu.

Wszystkie niezmienne wartości protokołu w jednym miejscu, aby w kodzie
serwera i klienta nie używać "magicznych liczb". Wartości zgodne ze
specyfikacją TCMP v1.0.

Format ramki (nagłówek stały = 49 bajtów, kodowanie big-endian):

    Offset  Rozmiar  Pole       Opis
    ------  -------  ---------  --------------------------------------------
    0x00    1B       VER        Wersja protokołu (aktualnie 0x01)
    0x01    1B       TYPE       Typ ramki (0x01-0x0A)
    0x02    1B       FLAGS      Flagi bitowe (bit 0 = MORE_DATA)
    0x03    8B       MSG_ID     Unikalny ID ramki, monotonicznie rosnący
    0x0B    4B       LENGTH     Długość payloadu w bajtach
    0x0F    2B       FRAG_NUM   Numer fragmentu, 0-based
    0x11    32B      HMAC       HMAC-SHA256 nagłówka i payloadu
    ------  -------  ---------  --------------------------------------------
    0x31    LENGTH   PAYLOAD    Treść zależna od TYPE
"""

# --------------------------------------------------------------------------- #
# Wersja protokołu i transport
# --------------------------------------------------------------------------- #
PROTOCOL_VERSION = 0x01          # wartość pola VER w nagłówku
DEFAULT_PORT = 7000              # port TCP nasłuchu serwera

# --------------------------------------------------------------------------- #
# Budowa ramki (offsety i rozmiary pól nagłówka, w bajtach)
# --------------------------------------------------------------------------- #
HEADER_LENGTH = 49               # stała długość nagłówka

OFFSET_VER = 0x00
OFFSET_TYPE = 0x01
OFFSET_FLAGS = 0x02
OFFSET_MSG_ID = 0x03
OFFSET_LENGTH = 0x0B
OFFSET_FRAG_NUM = 0x0F
OFFSET_HMAC = 0x11
OFFSET_PAYLOAD = 0x31            # == HEADER_LENGTH

SIZE_VER = 1
SIZE_TYPE = 1
SIZE_FLAGS = 1
SIZE_MSG_ID = 8
SIZE_LENGTH = 4
SIZE_FRAG_NUM = 2
SIZE_HMAC = 32                   # HMAC-SHA256

# --------------------------------------------------------------------------- #
# Kody typów ramek (pole TYPE)
# --------------------------------------------------------------------------- #
TYPE_HELLO = 0x01                # C -> S  Powitanie; wersja + identyfikator agenta
TYPE_AUTH = 0x02                 # C -> S  Uwierzytelnienie: login+hasło lub resume_token
TYPE_AUTH_OK = 0x03              # S -> C  Token sesyjny, klucz HMAC, liczba zakolejkowanych
TYPE_MSG = 0x04                  # C <-> S Wiadomość tekstowa (z obsługą fragmentacji)
TYPE_FILE = 0x05                 # C <-> S Fragment pliku graficznego (JPEG/PNG)
TYPE_ACK = 0x06                  # C <-> S Potwierdzenie odbioru ramki MSG/FILE
TYPE_PING = 0x07                 # C -> S  Keep-alive: żądanie potwierdzenia aktywności
TYPE_PONG = 0x08                 # S -> C  Keep-alive: odpowiedź na PING
TYPE_ERR = 0x09                  # S -> C  Błąd protokołu (kod + opis)
TYPE_BYE = 0x0A                  # C <-> S Czyste zamknięcie sesji z kodem powodu

# Zakres poprawnych typów (do walidacji -> ERR_UNKNOWN_TYPE)
TYPE_MIN = 0x01
TYPE_MAX = 0x0A

# Mapowanie kod -> nazwa (przydatne do logowania / debugowania)
TYPE_NAMES = {
    TYPE_HELLO: "HELLO",
    TYPE_AUTH: "AUTH",
    TYPE_AUTH_OK: "AUTH_OK",
    TYPE_MSG: "MSG",
    TYPE_FILE: "FILE",
    TYPE_ACK: "ACK",
    TYPE_PING: "PING",
    TYPE_PONG: "PONG",
    TYPE_ERR: "ERR",
    TYPE_BYE: "BYE",
}

# --------------------------------------------------------------------------- #
# Flagi bitowe (pole FLAGS)
# --------------------------------------------------------------------------- #
FLAG_MORE_DATA = 0x01            # bit 0 = 1 -> kolejne fragmenty następują
# bity 1-7 zarezerwowane, muszą być 0x00

# --------------------------------------------------------------------------- #
# Kody błędów (payload ramki ERR, pole error_code, 2B)
# --------------------------------------------------------------------------- #
ERR_UNSUPPORTED_VERSION = 0x0001   # fatalny: VER != PROTOCOL_VERSION
ERR_UNKNOWN_TYPE = 0x0002          # fatalny: TYPE poza zakresem 0x01-0x0A
ERR_PAYLOAD_TOO_LARGE = 0x0003     # fatalny: LENGTH > max dla danego TYPE
ERR_FILE_TOO_LARGE = 0x0004        # total_filesize > 5 MB
ERR_MALFORMED_PAYLOAD = 0x0005     # suma pól payloadu != LENGTH
ERR_INVALID_ENCODING = 0x0006      # nieprawidłowa sekwencja UTF-8
ERR_INCOMPLETE_FRAME = 0x0007      # fatalny: ramka niedostarczona w 10 s
ERR_DUPLICATE_MSG = 0x0008         # MSG_ID już widziany w sesji
ERR_AUTH_FAILED = 0x0009           # błędny login/hasło lub resume_token
ERR_AUTH_LIMIT = 0x000A            # fatalny: > 3 nieudane próby AUTH
ERR_TOKEN_EXPIRED = 0x000B         # fatalny: token sesyjny wygasł (24 h)
ERR_UNKNOWN_RECIPIENT = 0x000C     # recipient nie istnieje w systemie
ERR_RATE_LIMIT = 0x000D            # > 20 ramek MSG/FILE na 10 s
ERR_HMAC_INVALID = 0x000E          # fatalny: niepoprawny HMAC ramki
ERR_INVALID_FRAG = 0x000F          # FRAG_NUM niezgodny z oczekiwanym
ERR_INTERNAL = 0x0010              # fatalny: wewnętrzny błąd serwera

# Mapowanie kod -> nazwa
ERR_NAMES = {
    ERR_UNSUPPORTED_VERSION: "ERR_UNSUPPORTED_VERSION",
    ERR_UNKNOWN_TYPE: "ERR_UNKNOWN_TYPE",
    ERR_PAYLOAD_TOO_LARGE: "ERR_PAYLOAD_TOO_LARGE",
    ERR_FILE_TOO_LARGE: "ERR_FILE_TOO_LARGE",
    ERR_MALFORMED_PAYLOAD: "ERR_MALFORMED_PAYLOAD",
    ERR_INVALID_ENCODING: "ERR_INVALID_ENCODING",
    ERR_INCOMPLETE_FRAME: "ERR_INCOMPLETE_FRAME",
    ERR_DUPLICATE_MSG: "ERR_DUPLICATE_MSG",
    ERR_AUTH_FAILED: "ERR_AUTH_FAILED",
    ERR_AUTH_LIMIT: "ERR_AUTH_LIMIT",
    ERR_TOKEN_EXPIRED: "ERR_TOKEN_EXPIRED",
    ERR_UNKNOWN_RECIPIENT: "ERR_UNKNOWN_RECIPIENT",
    ERR_RATE_LIMIT: "ERR_RATE_LIMIT",
    ERR_HMAC_INVALID: "ERR_HMAC_INVALID",
    ERR_INVALID_FRAG: "ERR_INVALID_FRAG",
    ERR_INTERNAL: "ERR_INTERNAL",
}

# Kody błędów oznaczone jako fatalne (powodują zamknięcie połączenia)
FATAL_ERRORS = frozenset({
    ERR_UNSUPPORTED_VERSION,
    ERR_UNKNOWN_TYPE,
    ERR_PAYLOAD_TOO_LARGE,
    ERR_INCOMPLETE_FRAME,
    ERR_AUTH_LIMIT,
    ERR_TOKEN_EXPIRED,
    ERR_HMAC_INVALID,
    ERR_INTERNAL,
})

# --------------------------------------------------------------------------- #
# Wartości pól payloadu
# --------------------------------------------------------------------------- #
# ACK.status
ACK_STATUS_DELIVERED = 0x00      # dostarczono odbiorcy online
ACK_STATUS_QUEUED = 0x01         # zakolejkowano (odbiorca offline)

# BYE.reason
BYE_REASON_CLEAN = 0x00          # czyste zamknięcie sesji
BYE_REASON_TIMEOUT = 0x01        # zamknięcie z powodu timeoutu
BYE_REASON_ERROR = 0x02          # zamknięcie z powodu błędu

# FILE.mimetype_id
MIMETYPE_JPEG = 0x01             # image/jpeg
MIMETYPE_PNG = 0x02              # image/png

# AUTH.resume_token_len == RESUME_TOKEN_NONE -> brak tokenu wznowienia
RESUME_TOKEN_NONE = 0x0000

# --------------------------------------------------------------------------- #
# Limity i rozmiary
# --------------------------------------------------------------------------- #
MAX_CLIENT_AGENT = 128           # HELLO.client_agent, bajty UTF-8
MAX_USERNAME = 64                # login użytkownika, bajty UTF-8
MAX_RECIPIENT = 64               # login odbiorcy, bajty UTF-8
MAX_FILENAME = 128               # nazwa pliku, bajty UTF-8
MAX_ERR_MESSAGE = 256            # opis błędu w ramce ERR, bajty UTF-8
MAX_TEXT_PER_FRAGMENT = 65535    # MSG.text na fragment (2B pole długości)
MAX_FILE_SIZE = 5_242_880        # 5 MB - max total_filesize ramki FILE

SESSION_KEY_LENGTH = 32          # klucz HMAC z AUTH_OK (zawsze 32B)

STRING_LEN_FIELD = 2             # stringi poprzedzone 2-bajtowym polem długości

# --------------------------------------------------------------------------- #
# Timeouty (sekundy) i zasady keep-alive / rate-limiting
# --------------------------------------------------------------------------- #
TIMEOUT_HELLO = 60               # oczekiwanie na HELLO po połączeniu
TIMEOUT_AUTH = 60                # oczekiwanie na AUTH po HELLO
TIMEOUT_IDLE = 60                # bezczynność sesji (brak jakiejkolwiek ramki)
TIMEOUT_INCOMPLETE_FRAME = 10    # niekompletna ramka od pierwszego bajtu
TIMEOUT_FRAGMENT = 30            # brak kolejnego fragmentu FILE/MSG
SESSION_RESUME_WINDOW = 5 * 60   # ważność tokenu po rozłączeniu (5 min)
TOKEN_TTL = 24 * 60 * 60         # ważność tokenu sesyjnego (24 h)

PING_INTERVAL = 30               # klient wysyła PING co 30 s bezczynności
PONG_TIMEOUT = 30               # brak PONG przez 30 s -> utrata połączenia

AUTH_MAX_ATTEMPTS = 3            # limit nieudanych prób AUTH na połączenie
RATE_LIMIT_FRAMES = 20           # max ramek MSG/FILE ...
RATE_LIMIT_WINDOW = 10           # ... na 10 s dla danej sesji
