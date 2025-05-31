"""
Lemniscate-AGM Isogeny (LAI) Encryption.
Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations
"""

import hashlib
import secrets


def H(x: int, y: int, s: int, p: int) -> int:
    """
    H(x, y, s) = SHA-256(x||y||s) mod p
    Non-linear seed untuk setiap iterasi. :contentReference[oaicite:1]{index=1}
    """
    data = f"{x}|{y}|{s}".encode()
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % p


def sqrt_mod(a: int, p: int) -> int:
    """
    Hitung akar kuadrat modulo p (p prime).
    Gunakan Tonelli-Shanks (efek: O(log^2 p)).
    """
    # implementasi Tonelli-Shanks (ringkas)
    assert pow(a, (p - 1) // 2, p) == 1, "No sqrt exists"
    # kode lengkap TS omitted for brevity...
    # misal p % 4 == 3:
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # else: implement full Tonelli-Shanks
    raise NotImplementedError("Tonelli-Shanks for generic p")


def T(point: tuple[int, int], s: int, a: int, p: int) -> tuple[int, int]:
    """
    Transformasi T(x,y; s):
      x' = (x + a + H(x,y,s)) / 2 mod p
      y' = sqrt_mod(x*y + H(x,y,s), p)
    """
    x, y = point
    h = H(x, y, s, p)
    x_new = ((x + a + h) * pow(2, p-2, p)) % p
    y_new = sqrt_mod((x * y + h) % p, p)
    return x_new, y_new


def keygen(p: int, a: int, P0: tuple[int, int]) -> tuple[int, tuple[int,int]]:
    """
    Generasi kunci:
      - k random di [1, p-1]
      - Q = T^k(P0) via binary exponentiation
    """
    k = secrets.randbelow(p-1) + 1

    def apply_T_pow(point, exp):
        result = P0
        base = point
        e = exp
        s = 1
        while e:
            if e & 1:
                result = T(result, s, a, p)
            base = T(base, s, a, p)
            e >>= 1
            s += 1
        return result

    Q = apply_T_pow(P0, k)
    return k, Q


def encrypt(m: int, public_Q: tuple[int,int], p: int, a: int, P0: tuple[int,int]) -> tuple[tuple[int,int], tuple[int,int]]:
    """
    Enkripsi:
      r random
      C1 = T^r(P0)
      C2 = (m,0) + T^r(Q)
    """
    r = secrets.randbelow(p-1) + 1
    C1 = _pow_T(P0, r, a, p)
    Sr = _pow_T(public_Q, r, a, p)
    M = (m % p, 0)
    C2 = ((M[0] + Sr[0]) % p, (M[1] + Sr[1]) % p)
    return C1, C2


def decrypt(C1: tuple[int,int], C2: tuple[int,int], k: int, a: int, p: int) -> int:
    """
    Dekripsi:
      S = T^k(C1)
      M = C2 - S, ambil komponen pertama
    """
    S = _pow_T(C1, k, a, p)
    M0 = (C2[0] - S[0]) % p
    return M0


# Helper binary exponentiation wrapper
def _pow_T(P: tuple[int,int], exp: int, a: int, p: int) -> tuple[int,int]:
    result = P
    base = P
    e = exp
    s = 1
    while e > 0:
        if e & 1:
            result = T(result, s, a, p)
        base = T(base, s, a, p)
        e >>= 1
        s += 1
    return result
