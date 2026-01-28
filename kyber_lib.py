import secrets
import hashlib
import pickle
from typing import List, Tuple

# === PARAMETRY KYBER ===
N = 256
Q = 3329
K = 4
ETA = 2
DU = 11
DV = 5
N_INV = 3303

# === PRECOMPUTE ZETAS ===
def generate_zetas(root=17):
    zetas = [0] * 128
    powers = [pow(root, i, Q) for i in range(128)]
    for i in range(128):
        rev = 0
        tmp = i
        for _ in range(7):
            rev = (rev << 1) | (tmp & 1)
            tmp >>= 1
        zetas[rev] = powers[i]
    return zetas
ZETAS = generate_zetas()

# === MATH (NTT) ===
def ntt(p: List[int]) -> List[int]:
    a = list(p)
    length = 128
    k = 1
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
        length //= 2
    return a

def inv_ntt(p: List[int]) -> List[int]:
    a = list(p)
    length = 2
    while length <= 128:
        k = 128 // length
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            inv_zeta = pow(zeta, Q - 2, Q)
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                diff = (t - a[j + length]) % Q
                a[j + length] = (diff * inv_zeta) % Q
        length *= 2
    for i in range(N):
        a[i] = (a[i] * N_INV) % Q
    return a

def basemul(a0, a1, b0, b1, zeta):
    c0 = (a0 * b0 + a1 * b1 * zeta) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1

def poly_mul_ntt(a_ntt, b_ntt):
    c = [0] * N
    for i in range(N // 4):
        const_zeta = ZETAS[64 + i]
        c[4*i], c[4*i+1] = basemul(a_ntt[4*i], a_ntt[4*i+1], b_ntt[4*i], b_ntt[4*i+1], const_zeta)
        c[4*i+2], c[4*i+3] = basemul(a_ntt[4*i+2], a_ntt[4*i+3], b_ntt[4*i+2], b_ntt[4*i+3], -const_zeta)
    return c

# === POLY OBJECT ===
class PolyObj:
    def __init__(self, coeffs: List[int] = None):
        if coeffs is None: self.coeffs = [0] * N
        else:
            self.coeffs = [int(x) % Q for x in coeffs]
            if len(self.coeffs) < N: self.coeffs += [0] * (N - len(self.coeffs))
    def __add__(self, other): return PolyObj([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])
    def __sub__(self, other): return PolyObj([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])
    def __mul__(self, other):
        return PolyObj(inv_ntt(poly_mul_ntt(ntt(self.coeffs), ntt(other.coeffs))))

# === HELPERS ===
def csprng_bits(k: int) -> int: return secrets.randbits(k)

def cbd(eta: int) -> PolyObj:
    coeffs = []
    for _ in range(N):
        s1 = sum(csprng_bits(1) for _ in range(eta))
        s2 = sum(csprng_bits(1) for _ in range(eta))
        coeffs.append(s1 - s2)
    return PolyObj(coeffs)

def vec_add(v1, v2): return [a + b for a, b in zip(v1, v2)]
def vec_dot(v1, v2):
    s = PolyObj()
    for a, b in zip(v1, v2): s = s + (a * b)
    return s
def mat_vec_mul(M, v): return [vec_dot(row, v) for row in M]

def encode_message(m_int: int) -> PolyObj:
    bits = [(m_int >> i) & 1 for i in range(256)]
    coeffs = [(Q // 2) if b else 0 for b in bits]
    return PolyObj(coeffs)

def decode_message(p: PolyObj) -> int:
    out = 0
    for i in range(256):
        c = p.coeffs[i]
        dist_to_0 = min(c, Q - c)
        dist_to_half = min(abs(c - (Q//2)), abs(c - (Q//2) - Q), abs(c - (Q//2) + Q))
        if dist_to_half < dist_to_0: out |= (1 << i)
    return out

# === COMPRESSION ===
def compress_int(x, d): return ((x << d) + Q // 2) // Q & ((1 << d) - 1)
def decompress_int(y, d): return (y * Q + (1 << (d - 1))) >> d
def compress_poly(p, d): return PolyObj([compress_int(c, d) for c in p.coeffs])
def decompress_poly(p, d): return PolyObj([decompress_int(c, d) for c in p.coeffs])

# === MATRIX GEN ===
def parse_rejection_sampling(stream_bytes: bytes, n: int = 256) -> List[int]:
    coeffs = []
    i = 0
    while len(coeffs) < n and i + 2 < len(stream_bytes):
        b1 = stream_bytes[i]
        b2 = stream_bytes[i+1]
        b3 = stream_bytes[i+2]
        i += 3
        d1 = b1 + (b2 & 0x0F) * 256
        d2 = (b2 >> 4) + b3 * 16
        if d1 < Q: coeffs.append(d1)
        if len(coeffs) < n and d2 < Q: coeffs.append(d2)
    if len(coeffs) < n: coeffs += [0] * (n - len(coeffs))
    return coeffs

def gen_matrix_from_seed(rho: bytes) -> List[List[PolyObj]]:
    A = [[None for _ in range(K)] for _ in range(K)]
    for i in range(K):
        for j in range(K):
            input_bytes = rho + bytes([j, i])
            shake = hashlib.shake_128()
            shake.update(input_bytes)
            stream = shake.digest(840)
            coeffs = parse_rejection_sampling(stream)
            A[i][j] = PolyObj(coeffs)
    return A

# === CORE API ===
def keygen():
    rho = secrets.token_bytes(32)
    A = gen_matrix_from_seed(rho)
    s = [cbd(ETA) for _ in range(K)]
    e = [cbd(ETA) for _ in range(K)]
    t = vec_add(mat_vec_mul(A, s), e)
    return (t, rho), s

def encrypt(pk, m_int):
    t, rho = pk
    A = gen_matrix_from_seed(rho)
    r = [cbd(ETA) for _ in range(K)]
    e1 = [cbd(ETA) for _ in range(K)]
    e2 = cbd(ETA)
    A_T = [[A[j][i] for j in range(K)] for i in range(K)]
    u_poly_vec = vec_add(mat_vec_mul(A_T, r), e1)
    m_poly = encode_message(m_int)
    v_poly = vec_dot(t, r) + e2 + m_poly
    u_compressed = [compress_poly(p, DU) for p in u_poly_vec]
    v_compressed = compress_poly(v_poly, DV)
    return u_compressed, v_compressed

def decrypt(sk, ct):
    u_compressed, v_compressed = ct
    s = sk
    u_decompressed = [decompress_poly(p, DU) for p in u_compressed]
    v_decompressed = decompress_poly(v_compressed, DV)
    mn = v_decompressed - vec_dot(s, u_decompressed)
    return decode_message(mn)


# ==========================================
# NARZĘDZIA SIECIOWE (MODYFIKACJA TEXT)
# ==========================================

class KyberNetworkUtils:
    @staticmethod
    def encapsulate(pk, custom_message: str = None) -> Tuple[object, int]:
        """
        Teraz przyjmuje opcjonalny argument 'custom_message'.
        Jeśli go podasz, zaszyfruje Twój tekst.
        Jeśli nie, wygeneruje losowy sekret.
        """
        if custom_message:
            # 1. Zamiana tekstu na bajty, a potem na liczbę (int)
            message_bytes = custom_message.encode('utf-8')

            # SPRAWDZENIE DŁUGOŚCI: Max 32 bajty (256 bitów)
            if len(message_bytes) > 32:
                raise ValueError(f"Wiadomość za długa! Max 32 znaki. Twoja ma: {len(message_bytes)}")

            secret_int = int.from_bytes(message_bytes, 'big')
        else:
            # Domyślnie: losowe 256 bitów
            secret_int = secrets.randbits(256)

        # Enkapsulacja (Szyfrowanie)
        ciphertext = encrypt(pk, secret_int)

        return ciphertext, secret_int

    @staticmethod
    def decapsulate(sk, ciphertext) -> int:
        return decrypt(sk, ciphertext)

    @staticmethod
    def int_to_text(number: int) -> str:
        """Pomocnicza funkcja do odzyskania tekstu z liczby."""
        try:
            # Obliczamy ile bajtów zajmuje liczba (+7 // 8 to zaokrąglenie w górę)
            num_bytes = (number.bit_length() + 7) // 8
            return number.to_bytes(num_bytes, 'big').decode('utf-8')
        except:
            return "[Nie udało się odkodować tekstu]"

    @staticmethod
    def to_bytes(obj) -> bytes:
        return pickle.dumps(obj)

    @staticmethod
    def from_bytes(data: bytes):
        return pickle.loads(data)