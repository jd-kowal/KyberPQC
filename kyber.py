import random
from typing import List

# ============================
# PARAMETRY
# ============================
N = 256       # stopień pierścienia (wielomiany mają N współczynników)
Q = 3329      # modulo (jak w Kyberze)
K = 2         # wymiar macierzy (upraszczony Kyber: K=2)
ETA = 2       # parametr CBD (eta=2 typowy dla Kyber-512)

# ============================
# REPREZENTACJE
# ============================
Poly = List[int]  # reprezentacja wewnętrzna jako lista intów długości N

# ============================
# KLASA WIELOMIANU (prosta)
# ============================
class PolyObj:
    """Element pierścienia R_q = Z_q[X] / (X^N + 1). Reprezentowany jako lista N współczynników."""
    def __init__(self, coeffs: List[int] = None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            # wymuszamy długość N i redukcję modulo Q
            c = (coeffs + [0] * N)[:N]
            self.coeffs = [int(x) % Q for x in c]

    def __add__(self, other: 'PolyObj') -> 'PolyObj':
        return PolyObj([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other: 'PolyObj') -> 'PolyObj':
        return PolyObj([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __mul__(self, other: 'PolyObj') -> 'PolyObj':
        # konwolucja, potem redukcja modulo X^N + 1 (x^N ≡ -1)
        res = [0] * (2 * N)
        a = self.coeffs
        b = other.coeffs
        for i in range(N):
            ai = a[i]
            if ai == 0:
                continue
            for j in range(N):
                res[i + j] += ai * b[j]
        # redukcja x^{i+N} -> -x^i
        final = [(res[i] - res[i + N]) % Q for i in range(N)]
        return PolyObj(final)

    def copy(self) -> 'PolyObj':
        return PolyObj(self.coeffs[:])

    def __repr__(self):
        return f"PolyObj(len={N})"

    def to_list(self) -> List[int]:
        return self.coeffs[:]  # kopiuj

# ============================
# NARZĘDZIA / GENERATORY SZUMU
# ============================
def cbd(eta: int) -> PolyObj:
    """Centered binomial distribution CBD(eta) producing one polynomial of length N.
    Każdy współczynnik to różnica sumy eta bitów i kolejnej sumy eta bitów:
    value = sum_{i=1..eta} b_i - sum_{i=1..eta} b'_i  in [-eta..eta]
    """
    coeffs = []
    for _ in range(N):
        s1 = sum(random.getrandbits(1) for _ in range(eta))
        s2 = sum(random.getrandbits(1) for _ in range(eta))
        coeffs.append(s1 - s2)  # może być ujemne; PolyObj zredukuje do modulo Q
    return PolyObj(coeffs)

def generate_random_poly() -> PolyObj:
    """Losowy wielomian w R_q (używany jako element macierzy A)."""
    return PolyObj([random.randint(0, Q - 1) for _ in range(N)])

# ============================
# OPERACJE WECZKOWE / MACIERZOWE
# ============================
def vec_add(v1: List[PolyObj], v2: List[PolyObj]) -> List[PolyObj]:
    """Dodawanie wektorów wielomianów (element-wise)."""
    return [a + b for a, b in zip(v1, v2)]

def mat_vec_mul(M: List[List[PolyObj]], v: List[PolyObj]) -> List[PolyObj]:
    """Mnożenie macierzy M (KxK) przez wektor v (K) -> zwraca wektor K elementów PolyObj."""
    result = []
    for row in M:
        s = PolyObj()
        for i in range(len(row)):
            s = s + (row[i] * v[i])
        result.append(s)
    return result

def vec_dot(v1: List[PolyObj], v2: List[PolyObj]) -> PolyObj:
    """Iloczyn skalarny: sum_i v1_i * v2_i (wynik to PolyObj)."""
    s = PolyObj()
    for a, b in zip(v1, v2):
        s = s + (a * b)
    return s

# ============================
# ENCODING / DECODING WIADOMOSCI
# ============================
def encode_message(m_int: int, bits_to_use: int = 16) -> PolyObj:
    """Mapujemy liczbę m_int (0..2^bits_to_use-1) na wielomian:
       - kodujemy bits_to_use bitów (LSB -> coeff[0])
       - każdy bit=1 -> współczynnik = Q//2, bit=0 -> 0
       - pozostałe współczynniki = 0
    """
    if not (0 <= m_int < (1 << bits_to_use)):
        raise ValueError(f"message out of range for {bits_to_use} bits")
    bits = [(m_int >> i) & 1 for i in range(bits_to_use)]
    coeffs = [(Q // 2) if b == 1 else 0 for b in bits] + [0] * (N - bits_to_use)
    return PolyObj(coeffs)

def decode_message(p: PolyObj, bits_to_use: int = 16) -> int:
    """Dekoduje pierwsze bits_to_use współczynników, porównując odległość do 0 i do Q/2."""
    out = 0
    half = Q // 2
    for i in range(bits_to_use):
        c = p.coeffs[i]
        # porównujemy odległości w przestrzeni modulo Q:
        # odległość do 0
        d0 = min(abs(c - 0), abs(c - Q), abs(c + Q))
        # odległość do Q/2
        dh = min(abs(c - half), abs(c - (half - Q)), abs(c - (half + Q)))
        bit = 1 if dh < d0 else 0
        out |= (bit << i)
    return out

# ============================
# GENEROWANIE KLUCZA
# ============================
def keygen():
    """Zwraca: (pk, sk) gdzie pk = (A, t), sk = s"""
    print("[keygen] Generating keypair...")
    # Publiczna macierz A (K x K) - losowa
    A = [[generate_random_poly() for _ in range(K)] for _ in range(K)]
    # Sekret i szum małe z CBD
    s = [cbd(ETA) for _ in range(K)]
    e = [cbd(ETA) for _ in range(K)]
    # t = A * s + e
    t = vec_add(mat_vec_mul(A, s), e)
    pk = (A, t)
    sk = s
    return pk, sk

# ============================
# SZYFROWANIE / DESZYFROWANIE
# ============================
def encrypt(pk, message_int: int, bits_to_use: int = 16):
    """Zwraca (u, v) jako szyfrogram dla wiadomości message_int."""
    if not (0 <= message_int < (1 << bits_to_use)):
        raise ValueError("message out of allowed range")
    A, t = pk
    # losowy r i szumy (CBD)
    r = [cbd(ETA) for _ in range(K)]
    e1 = [cbd(ETA) for _ in range(K)]
    e2 = cbd(ETA)
    # u = A^T * r + e1
    A_T = [[A[j][i] for j in range(K)] for i in range(K)]
    u = vec_add(mat_vec_mul(A_T, r), e1)
    # m jako wielomian
    m_poly = encode_message(message_int, bits_to_use=bits_to_use)
    # v = t^T * r + e2 + m
    v_temp = vec_dot(t, r)
    v = v_temp + e2 + m_poly
    return (u, v)

def decrypt(sk, ciphertext, bits_to_use: int = 16):
    """Odwraca szyfrogram i zwraca zdekodowaną liczbę."""
    u, v = ciphertext
    s = sk
    su = vec_dot(s, u)
    m_noisy = v - su
    # dekoduj tylko pierwsze bits_to_use współczynników
    return decode_message(m_noisy, bits_to_use=bits_to_use)

# ============================
# DEMO / TEST
# ============================
if __name__ == "__main__":
    random.seed(0)  # for reproducibility in demo (usun lub zmień seed w produkcji)
    pk, sk = keygen()
    # testujemy 16-bitową wiadomość (0..65535)
    secret = 12345
    print(f"\nOriginal message: {secret}")
    ciphertext = encrypt(pk, secret, bits_to_use=16)
    recovered = decrypt(sk, ciphertext, bits_to_use=16)
    print(f"Recovered message: {recovered}")
    print("OK" if recovered == secret else "FAIL")
    # dodatkowo pokażmy, z jakim marginesem (przykładowe wartości współczynników)
    u, v = ciphertext
    mn = v - vec_dot(sk, u)
    print("\nSample noisy recovered coeffs (first 16):")
    print(mn.coeffs[:16])
