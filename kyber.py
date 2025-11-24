import random

# --- KONFIGURACJA (Uproszczona, edukacyjna) ---
# N=8 oznacza, że mamy 8 "slotów" w wielomianie, więc możemy przesłać 8 bitów.
N = 8       
Q = 3329      
K = 2       

print(f"--- Kyber EDU: N={N}, Q={Q} (Przesyłanie liczb 0-255) ---")

# --- KLASA WIELOMIANU ---
class Poly:
    """Reprezentuje element pierścienia R_q = Z_q[X] / (X^N + 1)"""
    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = (coeffs + [0]*N)[:N]
            self.coeffs = [c % Q for c in self.coeffs]

    def __add__(self, other):
        new_coeffs = [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Poly(new_coeffs)

    def __sub__(self, other):
        new_coeffs = [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Poly(new_coeffs)

    def __mul__(self, other):
        """Mnożenie z redukcją modulo X^N + 1"""
        res = [0] * (2 * N)
        for i in range(N):
            for j in range(N):
                res[i + j] = (res[i + j] + self.coeffs[i] * other.coeffs[j]) 
        
        final_coeffs = [0] * N
        for i in range(N):
            final_coeffs[i] = (res[i] - res[i + N]) % Q
            
        return Poly(final_coeffs)

    def __repr__(self):
        return str(self.coeffs)

# --- FUNKCJE POMOCNICZE ---

def generate_random_poly():
    return Poly([random.randint(0, Q-1) for _ in range(N)])

def generate_small_poly():
    """Szum: losuje wartości -1, 0, 1 modulo Q"""
    coeffs = []
    for _ in range(N):
        val = random.choice([-1, 0, 1])
        coeffs.append(val % Q)
    return Poly(coeffs)

def vec_add(v1, v2):
    return [x + y for x, y in zip(v1, v2)]

def mat_vec_mul(M, v):
    result = []
    for row in M:
        poly_sum = Poly()
        for i in range(len(row)):
            poly_sum = poly_sum + (row[i] * v[i])
        result.append(poly_sum)
    return result

def vec_dot(v1, v2):
    poly_sum = Poly()
    for x, y in zip(v1, v2):
        poly_sum = poly_sum + (x * y)
    return poly_sum

# --- 1. GENEROWANIE KLUCZY (Alice) ---
def keygen():
    print("\n[1] Generowanie kluczy...")
    A = [[generate_random_poly() for _ in range(K)] for _ in range(K)]
    s = [generate_small_poly() for _ in range(K)]
    e = [generate_small_poly() for _ in range(K)]
    
    # t = A * s + e
    t = vec_add(mat_vec_mul(A, s), e)
    
    return (A, t), s

# --- 2. SZYFROWANIE LICZBY 0-255 (Bob) ---
def encrypt(pk, message_int):
    # Walidacja zakresu dla N=8
    if not (0 <= message_int <= 255):
        raise ValueError(f"Wiadomość musi być z zakresu 0-255 (dla N={N})")

    print(f"\n[2] Szyfrowanie liczby: {message_int}")
    A, t = pk
    
    r = [generate_small_poly() for _ in range(K)]
    e1 = [generate_small_poly() for _ in range(K)]
    e2 = generate_small_poly()
    
    # u = A^T * r + e1
    A_T = [[A[j][i] for j in range(K)] for i in range(K)]
    u = vec_add(mat_vec_mul(A_T, r), e1)
    
    # Kodowanie wiadomości na wielomian
    # 1. Zamiana int na bity (np. 5 -> '00000101')
    # 2. Odwracamy kolejność ([::-1]), aby najmłodszy bit trafił do x^0
    bits = [int(b) for b in format(message_int, f'0{N}b')[::-1]]
    
    scale = Q // 2  # Wartość skalująca (ok. 8)
    
    # Jeśli bit=1 -> współczynnik = 8, jeśli bit=0 -> współczynnik = 0
    msg_coeffs = [scale if b == 1 else 0 for b in bits]
    m_poly = Poly(msg_coeffs)
    
    print(f"   Bity: {bits} -> Wielomian msg: {m_poly.coeffs}")

    # v = t^T * r + e2 + m_poly
    v_temp = vec_dot(t, r)
    v = v_temp + e2 + m_poly
    
    return (u, v)

# --- 3. ODSZYFROWYWANIE (Alice) ---
def decrypt(sk, ciphertext):
    print("\n[3] Odszyfrowywanie...")
    u, v = ciphertext
    s = sk
    
    # Noisy Message = v - s^T * u
    su = vec_dot(s, u)
    mn = v - su 
    
    print(f"   Odzyskany wielomian (z szumem): {mn.coeffs}")
    
    # Dekodowanie każdego współczynnika z osobna
    recovered_bits = []
    lower_bound = Q // 4       # ok. 4
    upper_bound = 3 * Q // 4   # ok. 12
    
    for coeff in mn.coeffs:
        # Sprawdzamy czy wartość jest bliżej Q/2 (czyli 1) czy 0
        # Dla Q=17, "jedynka" to wartości w środku zakresu (np. 5-12)
        if lower_bound < coeff < upper_bound:
            recovered_bits.append(1)
        else:
            recovered_bits.append(0)
            
    print(f"   Zdekodowane bity: {recovered_bits}")

    # Zamiana bitów z powrotem na int
    decrypted_int = 0
    for i, bit in enumerate(recovered_bits):
        decrypted_int += bit * (2**i)
        
    return decrypted_int

# --- GŁÓWNY PROGRAM ---
if __name__ == "__main__":
    # 1. Generowanie
    pk, sk = keygen()
    
    # 2. Testujemy liczbę z górnego zakresu bajtu
    # Możesz zmienić tę wartość na dowolną od 0 do 255
    tajna_liczba = 159 
    
    ciphertext = encrypt(pk, tajna_liczba)
    
    # 3. Wynik
    odzyskana_liczba = decrypt(sk, ciphertext)
    
    print(f"\n--- WYNIK ---")
    print(f"Wysłano: {tajna_liczba}")
    print(f"Odebrano: {odzyskana_liczba}")
    
    if tajna_liczba == odzyskana_liczba:
        print("Status: SUKCES (Wiadomość poprawna)")
    else:
        print("Status: BŁĄD (Szum był zbyt duży dla tak małego Q)")
