"""TCMPChat - serwer (tcmpchat-server).

Komponenty (w kolejności zależności):
  DatabaseLayer  - warstwa dostępu do SQLite (thread-safe)
  AuthModule     - rejestracja, logowanie, session resume (bcrypt)
  SessionManager - stan aktywnych sesji w pamięci
  ClientHandler  - wątek per klient, maszyna stanów TCMP
  TCMPServer     - pętla nasłuchu TLS + watchdog timeoutów

Uruchomienie:  python -m server.main --cert cert.pem --key key.pem
"""
