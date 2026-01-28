import socket
from kyber_lib import keygen, KyberNetworkUtils, K

# Konfiguracja
HOST = '0.0.0.0'
PORT = 65432


def start_persistent_server():
    print(f"[SERVER] Uruchamianie serwera Kyber (K={K})...")
    print("[SERVER] Czekam na wiadomości. Naciśnij Ctrl+C, aby zatrzymać.")

    counter = 0  # Licznik odebranych wiadomości

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Reset portu (żeby uniknąć błędu przy restarcie)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    counter += 1

                    # 1. Generujemy klucze
                    pk, sk = keygen()

                    # 2. Wysyłamy PK
                    conn.sendall(KyberNetworkUtils.to_bytes(pk))

                    # 3. Odbieramy Szyfrogram
                    data = conn.recv(16384)
                    if not data:
                        continue

                    ciphertext = KyberNetworkUtils.from_bytes(data)

                    # 4. Dekapsulacja (Matematyka)
                    recovered_int = KyberNetworkUtils.decapsulate(sk, ciphertext)

                    # 5. Zamiana liczby na tekst (Dla podglądu)
                    decoded_msg = KyberNetworkUtils.int_to_text(recovered_int)

                    # WYŚWIETLANIE WYNIKU
                    print(f"[#{counter}] Klient {addr[0]} -> ODSZYFROWANO: '{decoded_msg}'")

            except KeyboardInterrupt:
                print("\n[SERVER] Zatrzymywanie...")
                break
            except Exception as e:
                print(f"[SERVER] Błąd: {e}")


if __name__ == "__main__":
    start_persistent_server()