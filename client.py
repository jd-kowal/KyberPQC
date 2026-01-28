import socket
import time
import statistics
from kyber_lib import KyberNetworkUtils, K

# === KONFIGURACJA ===
SERVER_IP = '127.0.0.1'
PORT = 65432
N_TRIALS = 10  # Liczba prób


def run_benchmark():
    print(f"=== TEST WYDAJNOŚCI KYBER (K={K}) ===")
    print(f"Cel: {SERVER_IP}")
    print(f"Liczba prób: {N_TRIALS}")
    print("-" * 60)

    times = []

    for i in range(1, N_TRIALS + 1):
        # Tworzymy unikalną wiadomość dla każdej próby

        message_text = f"KyberTest_{i}"

        # === START POMIARU ===
        start_time = time.perf_counter()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_IP, PORT))

                # 1. Pobranie klucza
                data = s.recv(16384)
                pk = KyberNetworkUtils.from_bytes(data)

                # 2. Enkapsulacja (Szyfrowanie konkretnej wiadomości)
                ciphertext, _ = KyberNetworkUtils.encapsulate(pk, message_text)

                # 3. Wysłanie
                s.sendall(KyberNetworkUtils.to_bytes(ciphertext))

        except ConnectionRefusedError:
            print(f"Próba {i}: BŁĄD - Serwer nie odpowiada!")
            return
        except Exception as e:
            print(f"Próba {i}: BŁĄD - {e}")
            return

        # === KONIEC POMIARU ===
        end_time = time.perf_counter()

        duration_ms = (end_time - start_time) * 1000
        times.append(duration_ms)

        print(f"Próba {i:02d}: Wysłano '{message_text}' -> Czas: {duration_ms:.2f} ms")

        # Krótka przerwa dla stabilności socketa
        time.sleep(0.1)

    # === PODSUMOWANIE STATYSTYCZNE ===
    if times:
        avg_time = statistics.mean(times)
        stdev_time = statistics.stdev(times) if len(times) > 1 else 0.0

        print("\n" + "=" * 40)
        print(f"PODSUMOWANIE DLA KYBER (K={K}):")
        print(f"Średnia:              {avg_time:.2f} ms")
        print(f"Odchylenie (Jitter):  {stdev_time:.2f} ms")
        print(f"Najszybszy:           {min(times):.2f} ms")
        print(f"Najwolniejszy:        {max(times):.2f} ms")
        print("=" * 40)


if __name__ == "__main__":
    run_benchmark()