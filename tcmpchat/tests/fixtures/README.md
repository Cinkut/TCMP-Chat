# Certyfikaty testowe (e2e)

Pliki w tym katalogu służą **wyłącznie testom** `tests/test_e2e.py` i dotyczą
serwera na `localhost`. **Nie używać w produkcji.**

| Plik | Rola |
|------|------|
| `ca_cert.pem` | Certyfikat własnego CA. Klient ufa mu przez `cafile=`. |
| `server_cert.pem` | Certyfikat serwera, podpisany przez CA (SAN=localhost). |
| `server_key.pem` | Klucz prywatny serwera (testowy). |

Łańcuch jest CA-signed (nie self-signed) — zgodnie ze specyfikacją TCMP, która
dopuszcza w środowisku testowym własne CA pod warunkiem weryfikacji łańcucha
przez klienta.

## Regeneracja

```bash
bash tests/fixtures/gen_certs.sh
```

Wymaga `openssl`. Klucz CA nie jest zachowywany po podpisaniu.
