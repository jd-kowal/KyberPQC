import secrets
import hashlib  # Added for SHAKE-128 (needed for matrix expansion)
from typing import List

# ============================
# 1. CONSTANTS & PARAMETERS
# ============================
N = 256
Q = 3329
K = 2        # Kyber-512

ETA_1 = 3    # Noise parameter for KeyGen (ML-KEM-512)
ETA_2 = 2    # Noise parameter for Encrypt (ML-KEM-512)

# Compression parameters for Kyber-512 (according to FIPS 203)
DU = 10      # Compression bits for vector u
DV = 4       # Compression bits for polynomial v

# 128^-1 mod 3329 (Used for scaling after Inverse NTT)
# 128 * 3303 = 422784 = 1 mod 3329
N_INV = 3303

# ============================
# 2. PRECOMPUTE ZETAS
# ============================
def generate_zetas(root=17):
    """
    Generates the ZETAS table for Kyber (Bit-reversed powers of root).
    Root 17 is the 256-th primitive root of unity modulo 3329.
    """
    zetas = [0] * 128
    
    # 1. Calculate standard powers: 17^0, 17^1, ..., 17^127
    powers = [pow(root, i, Q) for i in range(128)]
    
    # 2. Reorder them using 7-bit bit-reversal
    #    (Kyber uses a specific bit-reversal order for the table)
    for i in range(128):
        # Bit reversal of 7-bit integer i
        rev = 0
        tmp = i
        for _ in range(7):
            rev = (rev << 1) | (tmp & 1)
            tmp >>= 1
        zetas[rev] = powers[i]
    return zetas

# Generate the authoritative table
ZETAS = generate_zetas()

# ============================
# 3. CORE MATH (NTT)
# ============================

def ntt(p: List[int]) -> List[int]:
    """
    Forward Number Theoretic Transform (Cooley-Tukey).
    Input: Standard Order -> Output: Bit-Reversed Order.
    """
    a = list(p)
    length = 128
    k = 1 # k tracks the index in ZETAS table
    
    # Layers: 128 -> 64 -> 32 -> ... -> 2
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
    """
    Inverse Number Theoretic Transform (Gentleman-Sande).
    Input: Bit-Reversed Order -> Output: Standard Order.
    """
    a = list(p)
    length = 2
    
    # Layers: 2 -> 4 -> 8 -> ... -> 128
    while length <= 128:
        # We need to match the 'k' used in the corresponding Forward layer.
        # In Forward NTT, 'k' starts at 1 and increments.
        # Layer len=128 used k=1. Layer len=64 used k=2..3. Layer len=2 used k=64..127.
        # So for InvNTT, we calculate the starting k for this length:
        k = 128 // length
        
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            
            # Use modular inverse of zeta for the inverse transform
            inv_zeta = pow(zeta, Q - 2, Q) 
            
            for j in range(start, start + length):
                # Gentleman-Sande Butterfly
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                
                # (a[j] - a[j+len]) * inv_zeta
                diff = (t - a[j + length]) % Q
                a[j + length] = (diff * inv_zeta) % Q
        length *= 2
        
    # Final scaling by 1/N
    for i in range(N):
        a[i] = (a[i] * N_INV) % Q
    return a

def basemul(a0, a1, b0, b1, zeta):
    """
    Multiplication in Rq[x] / (x^2 - zeta).
    """
    c0 = (a0 * b0 + a1 * b1 * zeta) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1

def poly_mul_ntt(a_ntt: List[int], b_ntt: List[int]) -> List[int]:
    """
    Point-wise multiplication in the NTT domain.
    """
    c = [0] * N
    for i in range(N // 4):
        # Base layer zetas correspond to indices 64..127
        const_zeta = ZETAS[64 + i] 
        
        # 1. First pair
        c[4*i], c[4*i+1] = basemul(
            a_ntt[4*i], a_ntt[4*i+1],
            b_ntt[4*i], b_ntt[4*i+1],
            const_zeta
        )
        
        # 2. Second pair (uses -zeta)
        c[4*i+2], c[4*i+3] = basemul(
            a_ntt[4*i+2], a_ntt[4*i+3],
            b_ntt[4*i+2], b_ntt[4*i+3],
            -const_zeta
        )
    return c

# ============================
# 4. POLYNOMIAL OBJECT
# ============================
class PolyObj:
    def __init__(self, coeffs: List[int] = None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = [int(x) % Q for x in coeffs]
            if len(self.coeffs) < N:
                self.coeffs += [0] * (N - len(self.coeffs))

    def __add__(self, other):
        return PolyObj([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other):
        return PolyObj([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __mul__(self, other):
        a_ntt = ntt(self.coeffs)
        b_ntt = ntt(other.coeffs)
        c_ntt = poly_mul_ntt(a_ntt, b_ntt)
        res = inv_ntt(c_ntt)
        return PolyObj(res)

# ============================
# 5. HELPERS (Updated for FIPS 203 RNG)
# ============================

# --- PRF oparta na SHAKE-256 ---
def prf(seed: bytes, nonce: int, length: int) -> bytes:
    """
    Pseudo-Random Function based on SHAKE-256.
    Used to expand seed into noise bytes for CBD.
    Input: 32-byte seed + 1-byte nonce.
    """
    shake = hashlib.shake_256()
    shake.update(seed + bytes([nonce]))
    return shake.digest(length)



def cbd(eta: int, coin_bytes: bytes) -> PolyObj:
    """
    Centered Binomial Distribution.
    Deterministic: consumes input bytes instead of using random().
    """
    coeffs = []
    
    # Convert bytes to bits for consumption
    bits = []
    for b in coin_bytes:
        for i in range(8):
            bits.append((b >> i) & 1)
            
    # Check if we have enough bits (2 * eta per coeff)
    if len(bits) < 2 * eta * N:
        raise ValueError("Not enough random bytes for CBD")

    idx = 0
    for _ in range(N):
        # Sample eta bits for 'a'
        a = sum(bits[idx + j] for j in range(eta))
        idx += eta
        # Sample eta bits for 'b'
        b = sum(bits[idx + j] for j in range(eta))
        idx += eta
        
        coeffs.append(a - b)
        
    return PolyObj(coeffs)

def vec_add(v1, v2): return [a + b for a, b in zip(v1, v2)]
def vec_dot(v1, v2):
    s = PolyObj()
    for a, b in zip(v1, v2):
        s = s + (a * b)
    return s
def mat_vec_mul(M, v):
    return [vec_dot(row, v) for row in M]

def encode_message(m_int: int) -> PolyObj:
    bits = [(m_int >> i) & 1 for i in range(256)]
    coeffs = [(Q // 2) if b else 0 for b in bits]
    return PolyObj(coeffs)

def decode_message(p: PolyObj) -> int:
    out = 0
    for i in range(256):
        c = p.coeffs[i]
        # Decryption Threshold: check if closer to 0 or Q/2
        # We transform c to check distance from Q/2 (1664)
        dist_to_0 = min(c, Q - c)
        dist_to_half = min(abs(c - (Q//2)), abs(c - (Q//2) - Q), abs(c - (Q//2) + Q))
        
        if dist_to_half < dist_to_0:
            out |= (1 << i)
    return out

# ============================
# 5.1 COMPRESSION HELPERS
# ============================
def compress_int(x: int, d: int) -> int:
    """
    Compresses integer x modulo Q to d bits.
    Formula: round((2^d / Q) * x) % 2^d
    """
    x = x % Q
    # Integer arithmetic equivalent of round(x * (2^d / Q))
    # We use (x * 2^d + Q//2) // Q
    return ((x << d) + Q // 2) // Q & ((1 << d) - 1)

def decompress_int(y: int, d: int) -> int:
    """
    Decompresses integer y (d bits) back to modulo Q.
    Formula: round((Q / 2^d) * y)
    """
    # Integer arithmetic equivalent of round(y * (Q / 2^d))
    return (y * Q + (1 << (d - 1))) >> d

def compress_poly(p: PolyObj, d: int) -> PolyObj:
    """Applies compression to all coefficients of a polynomial."""
    return PolyObj([compress_int(c, d) for c in p.coeffs])

def decompress_poly(p: PolyObj, d: int) -> PolyObj:
    """Applies decompression to all coefficients of a polynomial."""
    return PolyObj([decompress_int(c, d) for c in p.coeffs])

# ============================
# 6. MATRIX GENERATION (PROPER A DISTRIBUTION)
# ============================

# Function to parse SHAKE-128 output bytes into coefficients
# This implements Uniform Sampling modulo Q with Rejection Sampling
def parse_rejection_sampling(stream_bytes: bytes, n: int = 256) -> List[int]:
    """
    Parses a byte stream into N coefficients modulo Q.
    Uses the strategy where 3 bytes yield 2 12-bit integers.
    """
    coeffs = []
    i = 0
    # Process 3 bytes at a time
    while len(coeffs) < n and i + 2 < len(stream_bytes):
        b1 = stream_bytes[i]
        b2 = stream_bytes[i+1]
        b3 = stream_bytes[i+2]
        i += 3

        # d1 takes the first byte and the lower 4 bits of the second byte
        d1 = b1 + (b2 & 0x0F) * 256
        # d2 takes the upper 4 bits of the second byte and the third byte
        d2 = (b2 >> 4) + b3 * 16

        # Rejection sampling: if value >= Q, discard it
        if d1 < Q:
            coeffs.append(d1)
        # Check if we still need coeffs before adding the second one
        if len(coeffs) < n and d2 < Q:
            coeffs.append(d2)
            
    
    if len(coeffs) < n:
        coeffs += [0] * (n - len(coeffs))
        
    return coeffs

# Function to expand a 32-byte seed into the matrix A using SHAKE-128
def gen_matrix_from_seed(rho: bytes) -> List[List[PolyObj]]:
    """
    Determistically generates Matrix A (KxK) from a seed 'rho'.
    """
    A = [[None for _ in range(K)] for _ in range(K)]
    
    for i in range(K):
        for j in range(K):
            # Input to XOF is seed || j || i (standard coordinate encoding)
            input_bytes = rho + bytes([j, i])
            
            # Use SHAKE-128 (XOF) to generate a pseudo-random stream
            shake = hashlib.shake_128()
            shake.update(input_bytes)
            # We request enough bytes to likely find 256 valid coefficients
            stream = shake.digest(840) 
            
            # Convert bytes to polynomial coefficients
            coeffs = parse_rejection_sampling(stream)
            A[i][j] = PolyObj(coeffs)
    return A

# ============================
# 7. KEYGEN, ENCRYPT, DECRYPT
# ============================
def sanity_check_ntt():
    print("--- RUNNING MATH SANITY CHECK ---")
    test_poly = [i for i in range(N)]
    transformed = ntt(test_poly)
    recovered = inv_ntt(transformed)
    if recovered != test_poly:
        print("CRITICAL ERROR: NTT -> InvNTT does not return original!")
        print(f"Original[:5]: {test_poly[:5]}")
        print(f"Recovered[:5]: {recovered[:5]}")
        return False
    print("NTT Invertibility: OK")
    return True

def keygen():
    
    # 1. Random seed d (32 bytes)
    d = secrets.token_bytes(32)
    # 2. Random seed z (32 bytes)
    z = secrets.token_bytes(32)
    
    # 3. Expand d using G (SHA3-512) -> (rho, sigma)
    g_hash = hashlib.sha3_512()
    g_hash.update(d) 
    digest = g_hash.digest()
    rho, sigma = digest[:32], digest[32:] # rho for A, sigma for s/e

    # Expand 'rho' into matrix A
    A = gen_matrix_from_seed(rho)
    
    # Generate s and e using PRF on sigma
    # (Using FIPS 203 ETA_1 for KeyGen)
    s = []
    nonce = 0
    for _ in range(K):
        # Request enough bytes for 2*ETA*N bits
        coin_bytes = prf(sigma, nonce, 64 * ETA_1) 
        s.append(cbd(ETA_1, coin_bytes))
        nonce += 1
        
    e = []
    for _ in range(K):
        coin_bytes = prf(sigma, nonce, 64 * ETA_1)
        e.append(cbd(ETA_1, coin_bytes))
        nonce += 1    
    
    t = vec_add(mat_vec_mul(A, s), e)
    
    # Public Key now includes 'rho' so Bob can regenerate A
    return (t, rho), s

def encrypt(pk, m_int):
    # Unpack t and rho from Public Key
    t, rho = pk
    
    # Regenerate Matrix A from the seed 'rho'
    A = gen_matrix_from_seed(rho)
    
    # Generate random coins (32 bytes)
    coins = secrets.token_bytes(32)
    
    # Expand coins using PRF to generate r, e1, e2
    # (Using FIPS 203 ETA_2 for Encrypt)
    nonce = 0
    r = []
    for _ in range(K):
        coin_bytes = prf(coins, nonce, 64 * ETA_1) # Kyber-512 uses Eta1 for r
        r.append(cbd(ETA_1, coin_bytes))
        nonce += 1
        
    e1 = []
    for _ in range(K):
        coin_bytes = prf(coins, nonce, 64 * ETA_2) # Kyber-512 uses Eta2 for e1
        e1.append(cbd(ETA_2, coin_bytes))
        nonce += 1
        
    coin_bytes = prf(coins, nonce, 64 * ETA_2) # Kyber-512 uses Eta2 for e2
    e2 = cbd(ETA_2, coin_bytes)

    # Transpose A for encryption (A_T)
    A_T = [[A[j][i] for j in range(K)] for i in range(K)]

    # 1. Calculate uncompressed u and v
    u_poly_vec = vec_add(mat_vec_mul(A_T, r), e1)

    m_poly = encode_message(m_int)
    v_poly = vec_dot(t, r) + e2 + m_poly

    # 2. COMPRESS ciphertext components
    # Vector u is compressed to DU bits (10 bits for Kyber-512)
    u_compressed = [compress_poly(p, DU) for p in u_poly_vec]

    # Polynomial v is compressed to DV bits (4 bits for Kyber-512)
    v_compressed = compress_poly(v_poly, DV)

    return u_compressed, v_compressed

def decrypt(sk, ct):
    u_compressed, v_compressed = ct
    s = sk

    # 1. DECOMPRESS ciphertext components
    # We must decompress before doing arithmetic
    u_decompressed = [decompress_poly(p, DU) for p in u_compressed]
    v_decompressed = decompress_poly(v_compressed, DV)

    # 2. Standard decryption logic
    mn = v_decompressed - vec_dot(s, u_decompressed)

    return decode_message(mn)

if __name__ == "__main__":
    if not sanity_check_ntt():
        exit()

    print("[keygen] Generating keys...")
    pk, sk = keygen()
    
    secret = 1028
    print(f"Original message: {secret}")
    
    ct = encrypt(pk, secret)
    # Showing that we are using compression
    print(f"Ciphertext compressed (v[0] example): {ct[1].coeffs[0]} (should be < {2 ** DV})")

    rec = decrypt(sk, ct)
    
    print(f"Recovered message: {rec}")
    
    if rec == secret:
        print("SUCCESS!")
    else:
        print("FAIL")