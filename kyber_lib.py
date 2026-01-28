import secrets
import hashlib
import pickle
from typing import List, Tuple

# ============================
# 1. CONSTANTS & PARAMETERS (ML-KEM-512 / Kyber-512)
# ============================
N = 256
Q = 3329
K = 2

ETA_1 = 3    # Noise parameter for KeyGen
ETA_2 = 2    # Noise parameter for Encrypt

# Compression parameters
DU = 10      # Compression bits for vector u
DV = 4       # Compression bits for polynomial v

# 128^-1 mod 3329
N_INV = 3303

# ============================
# 2. PRECOMPUTE ZETAS
# ============================
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

# ============================
# 3. CORE MATH (NTT)
# ============================
def ntt(p: List[int]) -> List[int]:
    """Forward NTT."""
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
    """Inverse NTT."""
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

def poly_mul_ntt(a_ntt: List[int], b_ntt: List[int]) -> List[int]:
    c = [0] * N
    for i in range(N // 4):
        const_zeta = ZETAS[64 + i] 
        c[4*i], c[4*i+1] = basemul(
            a_ntt[4*i], a_ntt[4*i+1],
            b_ntt[4*i], b_ntt[4*i+1],
            const_zeta
        )
        c[4*i+2], c[4*i+3] = basemul(
            a_ntt[4*i+2], a_ntt[4*i+3],
            b_ntt[4*i+2], b_ntt[4*i+3],
            -const_zeta
        )
    return c

# ============================
# 4. POLYNOMIAL OBJECT (FIPS Compliant Domain Handling)
# ============================
class PolyObj:
    def __init__(self, coeffs: List[int] = None, is_ntt: bool = False):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = [int(x) % Q for x in coeffs]
            if len(self.coeffs) < N:
                self.coeffs += [0] * (N - len(self.coeffs))
        self.is_ntt = is_ntt

    def to_ntt(self):
        if self.is_ntt: return self
        return PolyObj(ntt(self.coeffs), is_ntt=True)

    def from_ntt(self):
        if not self.is_ntt: return self
        return PolyObj(inv_ntt(self.coeffs), is_ntt=False)

    def __add__(self, other):
        if self.is_ntt != other.is_ntt:
            a, b = self.to_ntt(), other.to_ntt()
            return PolyObj([(x + y) % Q for x, y in zip(a.coeffs, b.coeffs)], is_ntt=True)
        return PolyObj([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)], is_ntt=self.is_ntt)

    def __sub__(self, other):
        if self.is_ntt != other.is_ntt:
            a, b = self.to_ntt(), other.to_ntt()
            return PolyObj([(x - y) % Q for x, y in zip(a.coeffs, b.coeffs)], is_ntt=True)
        return PolyObj([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)], is_ntt=self.is_ntt)

    def __mul__(self, other):
        a = self.to_ntt()
        b = other.to_ntt()
        c_ntt = poly_mul_ntt(a.coeffs, b.coeffs)
        return PolyObj(c_ntt, is_ntt=True)

# ============================
# 5. FIPS 203 RNG & SAMPLING
# ============================
def prf(seed: bytes, nonce: int, length: int) -> bytes:
    """SHAKE-256 based PRF for deterministic noise generation."""
    shake = hashlib.shake_256()
    shake.update(seed + bytes([nonce]))
    return shake.digest(length)

def cbd(eta: int, coin_bytes: bytes) -> PolyObj:
    """Centered Binomial Distribution (Deterministic)."""
    coeffs = []
    bits = []
    for b in coin_bytes:
        for i in range(8):
            bits.append((b >> i) & 1)
    
    if len(bits) < 2 * eta * N:
        raise ValueError("Not enough random bytes for CBD")

    idx = 0
    for _ in range(N):
        a = sum(bits[idx + j] for j in range(eta))
        idx += eta
        b = sum(bits[idx + j] for j in range(eta))
        idx += eta
        coeffs.append(a - b)
        
    return PolyObj(coeffs, is_ntt=False)

def vec_add(v1, v2): return [a + b for a, b in zip(v1, v2)]
def vec_dot(v1, v2):
    s = PolyObj(is_ntt=v1[0].is_ntt)
    for a, b in zip(v1, v2): s = s + (a * b)
    return s
def mat_vec_mul(M, v): return [vec_dot(row, v) for row in M]

def encode_message(m_int: int) -> PolyObj:
    bits = [(m_int >> i) & 1 for i in range(256)]
    coeffs = [(Q // 2) if b else 0 for b in bits]
    return PolyObj(coeffs, is_ntt=False)

def decode_message(p: PolyObj) -> int:
    out = 0
    p_std = p.from_ntt()
    for i in range(256):
        c = p_std.coeffs[i]
        dist_to_0 = min(c, Q - c)
        dist_to_half = min(abs(c - (Q//2)), abs(c - (Q//2) - Q), abs(c - (Q//2) + Q))
        if dist_to_half < dist_to_0:
            out |= (1 << i)
    return out

# ============================
# 5.1 COMPRESSION
# ============================
def compress_int(x, d): return ((x << d) + Q // 2) // Q & ((1 << d) - 1)
def decompress_int(y, d): return (y * Q + (1 << (d - 1))) >> d
def compress_poly(p, d): return PolyObj([compress_int(c, d) for c in p.from_ntt().coeffs])
def decompress_poly(p, d): return PolyObj([decompress_int(c, d) for c in p.coeffs])

# ============================
# 6. MATRIX GENERATION (FIPS Compliant)
# ============================
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
    """Generates Matrix A directly in NTT domain (SampleNTT)."""
    A = [[None for _ in range(K)] for _ in range(K)]
    for i in range(K):
        for j in range(K):
            input_bytes = rho + bytes([j, i])
            shake = hashlib.shake_128()
            shake.update(input_bytes)
            stream = shake.digest(840) 
            coeffs = parse_rejection_sampling(stream)
            A[i][j] = PolyObj(coeffs, is_ntt=True)
    return A

# ============================
# 7. CORE API (KeyGen/Encrypt/Decrypt)
# ============================
def keygen():
    d = secrets.token_bytes(32)
    g_hash = hashlib.sha3_512()
    g_hash.update(d) 
    digest = g_hash.digest()
    rho, sigma = digest[:32], digest[32:]

    A = gen_matrix_from_seed(rho)
    
    s = []
    nonce = 0
    for _ in range(K):
        coin_bytes = prf(sigma, nonce, 64 * ETA_1) 
        s.append(cbd(ETA_1, coin_bytes))
        nonce += 1
        
    e = []
    for _ in range(K):
        coin_bytes = prf(sigma, nonce, 64 * ETA_1)
        e.append(cbd(ETA_1, coin_bytes))
        nonce += 1    
    
    t = vec_add(mat_vec_mul(A, s), e)
    return (t, rho), s

def encrypt(pk, m_int):
    t, rho = pk
    A = gen_matrix_from_seed(rho)
    
    # Random coins for encryption randomness
    coins = secrets.token_bytes(32)
    
    r = []
    nonce = 0
    for _ in range(K):
        coin_bytes = prf(coins, nonce, 64 * ETA_1) 
        r.append(cbd(ETA_1, coin_bytes))
        nonce += 1
        
    e1 = []
    for _ in range(K):
        coin_bytes = prf(coins, nonce, 64 * ETA_2)
        e1.append(cbd(ETA_2, coin_bytes))
        nonce += 1
        
    coin_bytes = prf(coins, nonce, 64 * ETA_2)
    e2 = cbd(ETA_2, coin_bytes)

    A_T = [[A[j][i] for j in range(K)] for i in range(K)]

    # 1. u = InvNTT(A^T * r) + e1
    u_ntt_temp = mat_vec_mul(A_T, r)
    u_poly_vec = [poly.from_ntt() + err for poly, err in zip(u_ntt_temp, e1)]

    # 2. v = InvNTT(t^T * r) + e2 + m
    v_ntt_temp = vec_dot(t, r)
    v_poly = v_ntt_temp.from_ntt() + e2 + encode_message(m_int)

    u_compressed = [compress_poly(p, DU) for p in u_poly_vec]
    v_compressed = compress_poly(v_poly, DV)

    return u_compressed, v_compressed

def decrypt(sk, ct):
    u_compressed, v_compressed = ct
    s = sk

    u_decompressed = [decompress_poly(p, DU) for p in u_compressed]
    v_decompressed = decompress_poly(v_compressed, DV)

    s_dot_u_ntt = vec_dot(s, u_decompressed) 
    mn = v_decompressed - s_dot_u_ntt.from_ntt() 

    return decode_message(mn)

# ============================
# 8. UTILITIES (Interface for client.py / server.py)
# ============================

class KyberNetworkUtils:
    @staticmethod
    def encapsulate(pk, custom_message: str = None) -> Tuple[object, int]:
        """
        Encapsulates a secret message (or random key) for the given public key.
        Matches the interface required by your client.py.
        """
        if custom_message:
            message_bytes = custom_message.encode('utf-8')
            if len(message_bytes) > 32:
                # Kyber encodes 256 bits = 32 bytes max
                raise ValueError(f"Message too long! Max 32 bytes. Yours: {len(message_bytes)}")
            secret_int = int.from_bytes(message_bytes, 'big')
        else:
            secret_int = secrets.randbits(256)

        ciphertext = encrypt(pk, secret_int)
        return ciphertext, secret_int

    @staticmethod
    def decapsulate(sk, ciphertext) -> int:
        """Decapsulates ciphertext using secret key."""
        return decrypt(sk, ciphertext)

    @staticmethod
    def int_to_text(number: int) -> str:
        """Helper to decode int back to text."""
        try:
            num_bytes = (number.bit_length() + 7) // 8
            return number.to_bytes(num_bytes, 'big').decode('utf-8')
        except:
            return "[Decoding Failed]"

    @staticmethod
    def to_bytes(obj) -> bytes:
        """Serializes object to bytes (using pickle for compatibility)."""
        return pickle.dumps(obj)

    @staticmethod
    def from_bytes(data: bytes):
        """Deserializes object from bytes."""
        return pickle.loads(data)