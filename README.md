# TCMPChat

Klient-serwer komunikatora terminalowego z własnym binarnym protokołem **TCMP**
(Text Chat Messaging Protocol, v1.0) działającym po TLS 1.3. Wiadomości tekstowe
i obrazy (JPEG/PNG), kolejkowanie dla użytkowników offline, integralność ramek
przez HMAC-SHA256 i wznawianie sesji po zerwaniu połączenia.

Implementacja w Pythonie 3.11+, biblioteka standardowa + `bcrypt` (jedyna
zależność zewnętrzna, po stronie serwera).

---

## Spis treści

- [Struktura projektu](#struktura-projektu)
- [Wymagania środowiskowe](#wymagania-środowiskowe)
- [Instrukcja uruchomienia](#instrukcja-uruchomienia)
- [Konfiguracja i przykładowe komendy](#konfiguracja-i-przykładowe-komendy)
- [Architektura](#architektura)
  - [Warstwa protokołu (`tcmp/`)](#warstwa-protokołu-tcmp)
  - [Serwer (`server/`)](#serwer-server)
  - [Klient (`client/`)](#klient-client)
  - [Baza danych (`db/`)](#baza-danych-db)
- [Format ramki TCMP](#format-ramki-tcmp)
- [Bezpieczeństwo](#bezpieczeństwo)
- [Testy](#testy)
- [Znane ograniczenia](#znane-ograniczenia)

---

## Struktura projektu

```
tcmpchat/
├── tcmp/                 # wspólna biblioteka protokołu (klient + serwer)
│   ├── constants.py      # stałe protokołu: typy, kody błędów, limity, timeouty
│   ├── errors.py         # TCMPError (kod błędu + flaga fatal)
│   ├── frame.py          # build/parse/validate/recv/send ramki + pack_string
│   ├── hmac_utils.py     # HMAC-SHA256 ramki, PRE_AUTH_TYPES, ZERO_HMAC
│   ├── fragment.py       # fragmentacja i reassembly payloadu (>65 535 B)
│   └── payloads.py       # encode_*/decode_* payloadów każdego typu ramki
├── server/
│   ├── main.py           # punkt wejścia (argparse), inicjalizacja zależności
│   ├── server.py         # TCMPServer: nasłuch TLS 1.3, thread-per-client, watchdog
│   ├── handler.py        # ClientHandler: maszyna stanów sesji, routing, kolejka
│   ├── session.py        # SessionManager: rejestr żywych sesji, rate-limit, anty-duplikat
│   ├── auth.py           # AuthModule: rejestracja/login/resume (bcrypt + secrets)
│   └── database.py       # DatabaseLayer: thread-safe SQLite
├── client/
│   ├── cli.py            # interaktywny klient terminalowy (pętla komend, callbacki)
│   ├── tcmp_client.py    # TCMPClient: połączenie, handshake, wysyłka/odbiór, keep-alive
│   └── protocol_messages.py  # cienki alias re-eksportujący tcmp.payloads
├── db/
│   ├── init.sql          # schemat SQLite (users, sessions, messages + indeksy)
│   └── seeding.py        # dane testowe (konta alice/bob/carol + kolejka)
├── tests/                # unittest (12 modułów, 172 testy)
│   └── fixtures/         # testowe CA + certyfikat serwera dla testów e2e
└── requirements.txt      # bcrypt>=4.0.0
```

---

## Wymagania środowiskowe

| Składnik | Wymaganie |
|----------|-----------|
| **Python** | 3.11 lub nowszy (kod używa składni `X | None`, `match`-friendly stdlib) |
| **System** | Windows / Linux / macOS (testowane na Windows 11 i Linuksie) |
| **Zależności Python** | `bcrypt >= 4.0.0` (tylko serwer) — `pip install -r requirements.txt` |
| **Biblioteka standardowa** | `socket`, `ssl`, `struct`, `hmac`, `hashlib`, `sqlite3`, `threading` — bez dodatkowych pakietów |
| **TLS** | moduł `ssl` ze stdlib (TLS 1.3); nie wymaga zewnętrznego OpenSSL w runtime |
| **OpenSSL (CLI)** | tylko opcjonalnie, do **wygenerowania** certyfikatów (`gen_certs.sh`) |
| **Certyfikat serwera** | wymagany do startu serwera (PEM); do testów lokalnych dołączony w `tests/fixtures/` |

Klient i wspólna biblioteka `tcmp/` korzystają **wyłącznie** z biblioteki
standardowej — `bcrypt` potrzebny jest tylko po stronie serwera (hashowanie haseł)
oraz w skrypcie seedującym.

---

## Instrukcja uruchomienia

Wszystkie polecenia uruchamiane są **z katalogu `tcmpchat/`**.

### 1. Zależności

```bash
pip install -r requirements.txt
```

### 2. (Opcjonalnie) baza z danymi testowymi

```bash
python db/seeding.py --db users.db
# zakłada konta: alice/alice123, bob/bob123, carol/carol123
# oraz kilka zakolejkowanych wiadomości (delivered=0)
```

Bez tego kroku baza powstaje automatycznie przy starcie serwera, a konta tworzą
się przy pierwszym logowaniu (komenda `/register`).

### 3. Certyfikat TLS

Do testów lokalnych można użyć gotowego CA z `tests/fixtures/` (SAN=`localhost`)
albo wygenerować własny:

```bash
bash tests/fixtures/gen_certs.sh   # wymaga openssl; klucz CA nie jest zachowywany
```

### 4. Serwer

```bash
python -m server.main \
    --cert tests/fixtures/server_cert.pem \
    --key  tests/fixtures/server_key.pem \
    --db   users.db
```

Domyślnie nasłuch na `0.0.0.0:7000`. Logi trafiają jednocześnie na stdout i do
pliku `tcmpchat-server.log`.

### 5. Klient

```bash
python -m client.cli --tls --cafile tests/fixtures/ca_cert.pem
```

Po starcie, w kliencie:

```
/register <user> <hasło>   załóż konto i zaloguj
/login <user> <hasło>      zaloguj
/chat <user>               ustaw aktywnego rozmówcę
<tekst>                     wyślij wiadomość do aktywnego rozmówcy
/file <ścieżka>            wyślij plik JPEG/PNG
/help                       lista komend
/quit                       czyste zamknięcie (BYE)
```

Odebrane pliki zapisywane są do katalogu `downloads/`.

---

## Konfiguracja i przykładowe komendy

### Parametry serwera (`python -m server.main`)

| Flaga | Domyślnie | Opis |
|-------|-----------|------|
| `--host` | `0.0.0.0` | adres nasłuchu |
| `--port` | `7000` | port TCP |
| `--cert` | (wymagane) | certyfikat TLS serwera (PEM) |
| `--key` | (wymagane) | klucz prywatny TLS (PEM) |
| `--db` | `users.db` | ścieżka do bazy SQLite |
| `--log-level` | `INFO` | `INFO` lub `DEBUG` |
| `--log-file` | `tcmpchat-server.log` | plik logów (pusty = tylko stdout) |

### Parametry klienta (`python -m client.cli`)

| Flaga | Domyślnie | Opis |
|-------|-----------|------|
| `--host` | `localhost` | adres serwera |
| `--port` | `7000` | port serwera |
| `--tls` | wył. | połączenie przez TLS 1.3 |
| `--cafile` | — | certyfikat CA do weryfikacji serwera |
| `--user` / `--password` | — | skrót auto-logowania (pomija `/login`) |
| `--auto-reconnect` | wył. | automatyczne wznawianie sesji po zerwaniu |
| `--verbose` | wył. | diagnostyka połączenia/TLS/handshake (`[VERBOSE]`) |

### Przykłady

```bash
# serwer na innym porcie, z logami DEBUG
python -m server.main --port 9000 --cert ... --key ... --log-level DEBUG

# klient z auto-logowaniem i automatycznym reconnectem
python -m client.cli --tls --cafile tests/fixtures/ca_cert.pem \
    --user alice --password alice123 --auto-reconnect

# klient z pełną diagnostyką handshake'u TLS
python -m client.cli --tls --cafile tests/fixtures/ca_cert.pem --verbose
```

---

## Architektura

### Warstwa protokołu (`tcmp/`)

Jedno źródło prawdy dla obu stron. `import tcmp` re-eksportuje całe publiczne API
(stałe, `TCMPError`, funkcje ramek/fragmentów/payloadów), więc serwer i klient
kodują/dekodują w dokładnie ten sam sposób.

- **`frame.py`** — niskopoziomowe operacje na 49-bajtowym nagłówku (big-endian):
  - `build_frame` składa nagłówek + HMAC + payload. Dla `PRE_AUTH_TYPES`
    (HELLO/AUTH/AUTH_OK) wpisuje `ZERO_HMAC`; dla pozostałych wymaga
    `session_key`. ERR/BYE mogą wyjątkowo powstać przed ustanowieniem sesji
    (np. `ERR_UNSUPPORTED_VERSION` na złym HELLO) — wtedy też zerowy HMAC.
  - `parse_frame` rozkłada bajty na słownik pól; sprawdza spójność długości.
  - `validate_frame` egzekwuje reguły dające się ocenić z samej ramki
    (VER, TYPE w zakresie, zarezerwowane bity FLAGS, górny limit LENGTH) i —
    gdy podano `session_key` — weryfikuje HMAC.
  - `recv_frame` czyta ramkę ze strumienia i **odrzuca deklaracje
    `LENGTH > MAX_FRAME_PAYLOAD` zanim cokolwiek zaalokuje** (ochrona DoS —
    pole LENGTH ma 4 B, więc bez limitu atakujący mógłby zadeklarować ~4 GB).
- **`hmac_utils.py`** — HMAC-SHA256 liczony z `nagłówek_bez_pola_HMAC + payload`,
  porównanie w czasie stałym (`hmac.compare_digest`).
- **`fragment.py`** — payload > 65 535 B dzielony jest na fragmenty wspólnym
  `MSG_ID`, z flagą `MORE_DATA` na wszystkich oprócz ostatniego.
  `ReassemblyBuffer` skleja je z powrotem, wymusza kolejność `FRAG_NUM`
  (`ERR_INVALID_FRAG` przy luce) i porzuca niekompletne strumienie po 30 s.
- **`payloads.py`** — `encode_*`/`decode_*` dla każdego typu. Payload MSG to
  `sender | recipient | timestamp(8B) | text`; FILE dokłada `filename`,
  `mimetype_id` i `total_filesize`. Pole `sender` od klienta jest **nieufne** —
  serwer je nadpisuje (patrz niżej).

### Serwer (`server/`)

Model **thread-per-client**: każde połączenie obsługuje osobny wątek
`ClientHandler`; współdzielone są tylko `DatabaseLayer`, `AuthModule` i
`SessionManager`.

**Maszyna stanów sesji** (`handler.py`):

```
CONNECTED → HELLO_RECEIVED → AUTHENTICATED → DELIVERING_QUEUE → MESSAGING → CLOSING
```

1. **CONNECTED** — oczekiwanie na HELLO (timeout 60 s), weryfikacja wersji.
2. **AUTH** — login+hasło lub `resume_token`. Konto zakładane przy pierwszym
   logowaniu; po 3 nieudanych próbach `ERR_AUTH_LIMIT` + BYE.
3. **DELIVERING_QUEUE** — po AUTH_OK serwer wypycha zaległe wiadomości
   (delivered=0) i czeka na ACK każdej z nich.
4. **MESSAGING** — routing MSG/FILE: jeśli odbiorca online → przekazanie do
   jego gniazda i `ACK delivered`; offline → zapis do bazy i `ACK queued`.
   Każda wiadomość jest też persistowana. Obsługa PING→PONG, BYE.

Kluczowe zachowania:

- **Anti-spoofing** (`_restamp_sender`): pole `sender` w MSG/FILE jest
  nadpisywane uwierzytelnioną nazwą z sesji, zanim ramka trafi do routingu i
  bazy — klient nie może podszyć się pod kogoś innego.
- **Nigdy nie logujemy treści** wiadomości — wyłącznie metadane (typ, MSG_ID,
  długość, nadawca→odbiorca).
- **Watchdog** (osobny wątek): co 15 s zamyka sesje bezczynne >60 s
  (`reap_idle` wysyła BYE i `shutdown` gniazda; IO wykonywane poza lockiem
  rejestru, by uniknąć zakleszczenia).

**`SessionManager`** — rejestr żywych sesji w pamięci chroniony jednym lockiem.
Trzyma per-sesja: gniazdo, klucz, licznik MSG_ID, zbiór widzianych MSG_ID
(anty-duplikat → `ERR_DUPLICATE_MSG`) i okno czasowe rate-limitu
(20 ramek / 10 s → `ERR_RATE_LIMIT`).

**`AuthModule`** — `bcrypt` (losowy salt per użytkownik), tokeny i klucze HMAC z
`secrets`. Login i hasło zwracają **identyczny** komunikat „Invalid credentials”
(ochrona przed enumeracją kont). `resume` rotuje token i klucz.

**`DatabaseLayer`** — jedno połączenie SQLite `check_same_thread=False` + jeden
`threading.Lock` serializujący wszystkie operacje. Schemat z `db/init.sql`.

### Klient (`client/`)

**`TCMPClient`** (`tcmp_client.py`) — logika protokołu, niezależna od UI:

- Połączenie TCP, opcjonalnie TLS 1.3 z weryfikacją łańcucha (`cafile`).
- Handshake HELLO → AUTH → AUTH_OK; `login()` i `resume()` (przez wspólny
  `_read_auth_reply`).
- Wysyłka `send_message`/`send_file` z automatyczną fragmentacją i śledzeniem
  ACK (`_pending`). MSG_ID monotoniczny per sesja, od 1.
- **Wątek odbiorczy** (`_recv_loop`) waliduje każdą ramkę (w tym HMAC),
  składa fragmenty, odsyła ACK i woła callbacki (`on_message`, `on_file`,
  `on_ack`, `on_error`, …).
- **Keep-alive** (`_keepalive_loop`): PING po 30 s bezczynności; brak PONG przez
  30 s → utrata połączenia.
- **Auto-reconnect** (opcjonalny): po zerwaniu wątek wznawia sesję przez
  `resume()` z backoffem (token ważny 5 min po nagłym rozłączeniu).

**`cli.py`** — interaktywna nakładka. `CLISession` trzyma stan lokalny
(aktywny rozmówca przeżywa reconnect). `handle_command` jest wydzielone z pętli
stdin, więc jest testowalne bez sieci. Callbacki formatują linie z czasem:
`[HH:MM:SS] <nadawca>: <treść>` (fallback `??:??:??` przy braku/błędnym
znaczniku). Odebrane pliki zapisywane są przez `os.path.basename` — ochrona
przed path traversal z nazwy nadawcy.

### Baza danych (`db/`)

SQLite, schemat w `init.sql` (idempotentny `CREATE TABLE IF NOT EXISTS`,
`WAL` + `foreign_keys=ON`):

| Tabela | Rola |
|--------|------|
| `users` | konto: `username` (unikalny, 1–64 znaki), `password_hash` (bcrypt) |
| `sessions` | token sesyjny (24 h), 32-bajtowy `session_key`, `resume_expires_at` (okno 5 min po rozłączeniu) |
| `messages` | `sender`/`recipient` (login), `type` (4=MSG, 5=FILE), `payload` (bajty po reassembly), `timestamp`, `delivered` |

Indeksy pod główne zapytania: lookup tokenu, sprawdzanie online, dostarczanie
kolejki (`recipient, delivered, id`).

`seeding.py` zakłada konta testowe i kolejkę niedostarczonych wiadomości,
kodując payload przez `tcmp.payloads.encode_msg` (ten sam format co produkcyjny).

---

## Format ramki TCMP

Nagłówek stały **49 B**, big-endian, następnie zmienny PAYLOAD:

| Offset | Rozmiar | Pole | Opis |
|--------|---------|------|------|
| 0x00 | 1 B | VER | wersja protokołu (0x01) |
| 0x01 | 1 B | TYPE | typ ramki (0x01–0x0A) |
| 0x02 | 1 B | FLAGS | bit 0 = MORE_DATA, reszta zarezerwowana |
| 0x03 | 8 B | MSG_ID | identyfikator ramki, monotoniczny per sesja |
| 0x0B | 4 B | LENGTH | długość payloadu |
| 0x0F | 2 B | FRAG_NUM | numer fragmentu (0-based) |
| 0x11 | 32 B | HMAC | HMAC-SHA256(nagłówek bez HMAC + payload) |
| 0x31 | LENGTH | PAYLOAD | treść zależna od TYPE |

Typy: `HELLO 0x01`, `AUTH 0x02`, `AUTH_OK 0x03`, `MSG 0x04`, `FILE 0x05`,
`ACK 0x06`, `PING 0x07`, `PONG 0x08`, `ERR 0x09`, `BYE 0x0A`.

Stringi w payloadzie są prefiksowane 2-bajtową długością. Pełną listę kodów
błędów i limitów zawiera `tcmp/constants.py`.

---

## Bezpieczeństwo

- **TLS 1.3 obowiązkowy** — serwer wymusza `minimum_version = TLSv1_3` i odrzuca
  połączenia bez udanego handshake'u; klient weryfikuje łańcuch certyfikatów.
- **Integralność ramek** — HMAC-SHA256 z kluczem sesyjnym na każdej ramce
  po uwierzytelnieniu; weryfikacja w czasie stałym, `ERR_HMAC_INVALID` (fatalny)
  przy niezgodności.
- **Hasła** — bcrypt z losowym saltem; identyczny komunikat błędu logowania
  (brak enumeracji kont).
- **Anti-spoofing nadawcy** — serwer nadpisuje pole `sender` nazwą z sesji.
- **Ochrona zasobów** — limit `LENGTH` w `recv_frame` (DoS), rate-limit
  20 ramek/10 s, limit pliku 5 MB, anty-duplikat MSG_ID, timeouty faz.
- **Brak treści w logach** — logowane wyłącznie metadane.

---

## Testy

Zestaw testów to **173 przypadki w 12 modułach** uruchamiane wbudowanym
`unittest` (bez pytest). Pokrywają zarówno ścieżki poprawne (round-tripy
kodowania, dostarczanie wiadomości), jak i **scenariusze błędne** (złe hasło,
manipulacja ramką, duplikaty, rate-limit, fragmenty nie po kolei).

### Uruchomienie

```bash
# wszystkie testy (z katalogu tcmpchat/)
python -m unittest discover -s tests -v

# pojedynczy moduł
python -m unittest tests.test_cli -v
```

Ran 173 tests in 26.232s

OK

### Co sprawdzają poszczególne moduły

| Moduł(y) | Obszar | Przykładowe sprawdzenia |
|----------|--------|--------------------------|
| `test_constants` | spójność stałych protokołu | unikalność i zakres kodów typów/błędów, layout nagłówka 49 B, limity (plik 5 MB, klucz 32 B) |
| `test_frame`, `test_hmac_utils` | warstwa ramki + integralność | round-trip build/parse, big-endian, zerowy vs prawdziwy HMAC, **wykrycie zmanipulowanego nagłówka/payloadu**, odczyt ze strumienia, zamknięte połączenie |
| `test_fragment` | fragmentacja i składanie | podział na granicy 65 535 B, kolejność `FRAG_NUM`, **fragment poza kolejnością → błąd**, przeplot wielu wiadomości, porzucanie częściowych |
| `test_protocol_messages` | kodowanie payloadów (encode/decode) | round-tripy MSG/FILE/AUTH/ACK/ERR/BYE, UTF-8, **odrzucenie zbyt długich pól, złego mimetype, pliku > 5 MB** |
| `test_auth`, `test_database` | uwierzytelnianie + warstwa SQLite | rejestracja/login, **hasło nie w plaintext, identyczny błąd przy złym loginie i haśle**, rotacja tokenu przy resume, kolejka wiadomości, wygasłe sesje |
| `test_session` | stan sesji w pamięci | licznik MSG_ID (w tym thread-safe), **anty-duplikat, rate-limit z oknem czasowym**, watchdog ubijający bezczynne sesje |
| `test_handler` | routing po stronie serwera | dostarczenie online vs kolejka offline, **nieznany odbiorca / duplikat / rate-limit → błąd**, nadpisanie `sender`, walidacja FILE |
| `test_cli` | parser komend i UI klienta | komendy `/chat`/`/file`, wymóg logowania, format `[HH:MM:SS] nadawca: treść`, **ochrona przed path traversal** przy zapisie pliku |
| `test_client_integration` | klient jako całość (na atrapach gniazd) | pełny handshake, wielofragmentowy plik, śledzenie ACK, keep-alive (PING gdy bezczynny, rozłączenie przy braku PONG), **odrzucenie ramki ze złym HMAC** |
| `test_e2e` | pełny scenariusz po TLS | prawdziwy serwer + klient na `localhost`: dostarczenie z kolejki, **odrzucenie złego hasła**, session resume i auto-reconnect po nagłym zerwaniu |

Testy `test_e2e` korzystają z certyfikatów w `tests/fixtures/` (własne CA,
SAN=`localhost`) i stanowią najbliższe odwzorowanie realnego użycia: weryfikują
protokół end-to-end przez gniazda TLS, łącznie ze ścieżkami odporności
(rozłączenie → wznowienie sesji).

---

## Znane ograniczenia

- **Rejestracja = pierwsze logowanie (TOFU).** Protokół nie rozróżnia rejestracji
  od logowania — konto powstaje przy pierwszym `/login`/`/register` dla nieznanej
  nazwy. Nie ma osobnego potwierdzenia ani odzyskiwania hasła.
- **Pliki: tylko JPEG/PNG, do 5 MB.** Inne typy i większe rozmiary są odrzucane
  (`ERR_FILE_TOO_LARGE` / walidacja mimetype).
- **Stan ulotny w pamięci.** Rejestr sesji, liczniki anty-duplikat i okna
  rate-limitu żyją w pamięci procesu — restart serwera je zeruje (trwałe są tylko
  konta, sesje i wiadomości w SQLite).
- **SQLite z jednym globalnym lockiem.** Wszystkie operacje bazodanowe są
  serializowane jednym `threading.Lock` — świadomy kompromis prostoty nad
  współbieżnością; przy dużym obciążeniu baza jest wąskim gardłem.
- **Brak listy kontaktów / historii w kliencie.** Klient pokazuje wiadomości na
  bieżąco; nie ma przeglądania archiwum (mimo że serwer persistuje wiadomości).
- **Certyfikaty testowe.** Fixtures w `tests/fixtures/` służą wyłącznie testom
  na `localhost` — nie używać w produkcji.
- **`test_fragment.test_timeout_discards_stale`** bywa niestabilny na Windows
  (gruba rozdzielczość zegara monotonicznego przy progu timeoutu 0).
