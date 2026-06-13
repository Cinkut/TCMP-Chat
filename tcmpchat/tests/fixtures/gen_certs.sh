#!/usr/bin/env bash
# Generuje testowe certyfikaty TLS dla e2e: własne CA + certyfikat serwera
# podpisany tym CA (leaf CA-signed, SAN=localhost). Zgodne ze specyfikacją
# TCMP (self-signed bez CA jest niedopuszczalny; w teście dozwolone własne CA).
#
# Pliki wynikowe (w katalogu tego skryptu):
#   ca_cert.pem      - certyfikat CA; klient ufa mu przez cafile=
#   server_cert.pem  - certyfikat serwera podpisany przez CA
#   server_key.pem   - klucz prywatny serwera
#
# Użycie:  bash gen_certs.sh
#
# Wymaga: openssl. Certyfikaty są TYLKO testowe (localhost) - nie używać
# w produkcji. Klucz CA nie jest zachowywany.
set -euo pipefail

# Git Bash na Windows przerabia "/CN=..." na ścieżkę - wyłączamy konwersję.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")"

DAYS=3650

echo "[1/3] Generowanie CA..."
openssl req -x509 -newkey rsa:2048 -keyout ca_key.pem -out ca_cert.pem \
  -days "$DAYS" -nodes -subj "/CN=TCMP Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo "[2/3] Klucz i CSR serwera..."
openssl req -newkey rsa:2048 -keyout server_key.pem -out server.csr \
  -nodes -subj "/CN=localhost" 2>/dev/null

cat > server_ext.cnf <<'EOF'
subjectAltName=DNS:localhost
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

echo "[3/3] Podpisywanie certyfikatu serwera przez CA..."
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out server_cert.pem -days "$DAYS" -extfile server_ext.cnf 2>/dev/null

# Sprzątanie: CSR, plik rozszerzeń, serial i KLUCZ CA (niepotrzebny po podpisaniu).
rm -f server.csr server_ext.cnf ca_cert.srl ca_key.pem

echo "--- weryfikacja łańcucha ---"
openssl verify -CAfile ca_cert.pem server_cert.pem
openssl x509 -in server_cert.pem -noout -ext subjectAltName | tail -1
echo "Gotowe: ca_cert.pem, server_cert.pem, server_key.pem"
