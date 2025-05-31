"""
Lemniscate-AGM Isogeny (LAI) Encryption.
Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations
"""

import hashlib
import secrets
from typing import Optional, Tuple


def H(x: int, y: int, s: int, p: int) -> int:
    """
    H(x, y, s) = SHA-256(x || y || s) mod p
    Non-linear seed untuk setiap iterasi.
    """
    data = f"{x}|{y}|{s}".encode()
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % p


def sqrt_mod(a: int, p: int) -> Optional[int]:
    """
    Hitung akar kuadrat modulo p (p prime) menggunakan Tonelli–Shanks.
    Jika 'a' bukan kuadrat residu mod p, kembalikan None.
    """
    # Kasus sederhana: jika a ≡ 0 mod p → akar = 0
    a = a % p
    if a == 0:
        return 0

    # Legendre symbol: a^((p-1)/2) mod p
    ls = pow(a, (p - 1) // 2, p)
    if ls == p - 1:
        # a adalah non-residu kuadrat modulo p
        return None

    # Jika p ≡ 3 (mod 4), gunakan rumus langsung
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Tonelli–Shanks untuk p ≡ 1 (mod 4)
    # Tulis p-1 = q * 2^s dengan q ganjil
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Cari z: kuadrat non-residu
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    # Inisiasi variabel
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    # Loop Tonelli–Shanks
    while True:
        if t % p == 1:
            return r
        # Cari i terkecil: t^(2^i) ≡ 1 mod p
        t2i = t
        i = 0
        for i2 in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                i = i2
                break

        # Update variabel
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p


def T(point: Tuple[int, int], s: int, a: int, p: int) -> Tuple[int, int]:
    """
    Transformasi T(x, y; s):
      x' = (x + a + H(x,y,s)) * inv2 mod p
      y' = sqrt_mod(x*y + H(x,y,s), p)
    Jika sqrt_mod gagal (None), ditangani dengan menaikkan s (fallback).
    """
    x, y = point
    inv2 = pow(2, p - 2, p)  # invers dari 2 mod p

    trials = 0
    s_current = s
    while trials < 10:
        h = H(x, y, s_current, p)
        x_candidate = ((x + a + h) * inv2) % p
        y_sq = (x * y + h) % p
        y_candidate = sqrt_mod(y_sq, p)
        if y_candidate is not None:
            return x_candidate, y_candidate

        # Fallback: naikkan s dan coba lagi
        s_current += 1
        trials += 1

    raise ValueError(
        f"T: Gagal menemukan sqrt untuk y^2={y_sq} mod {p} setelah {trials} percobaan."
    )


def _pow_T(P: Tuple[int, int], exp: int, a: int, p: int) -> Tuple[int, int]:
    """
    Binary exponentiation wrapper untuk T.
    Menghitung T^exp(P) secara efisien.
    """
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


def keygen(p: int, a: int, P0: Tuple[int, int]) -> Tuple[int, Tuple[int, int]]:
    """
    Generasi kunci:
      - Pilih k random di [1, p-1]
      - Hitung Q = T^k(P0) via binary exponentiation
    """
    k = secrets.randbelow(p - 1) + 1
    Q = _pow_T(P0, k, a, p)
    return k, Q


def encrypt(
    m: int,
    public_Q: Tuple[int, int],
    p: int,
    a: int,
    P0: Tuple[int, int],
) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Enkripsi:
      r random
      C1 = T^r(P0)
      Sr = T^r(Q)
      M = (m mod p, 0)
      C2 = M + Sr
    """
    r = secrets.randbelow(p - 1) + 1
    C1 = _pow_T(P0, r, a, p)
    Sr = _pow_T(public_Q, r, a, p)
    M = (m % p, 0)
    C2 = ((M[0] + Sr[0]) % p, (M[1] + Sr[1]) % p)
    return C1, C2


def decrypt(
    C1: Tuple[int, int],
    C2: Tuple[int, int],
    k: int,
    a: int,
    p: int,
) -> int:
    """
    Dekripsi:
      S = T^k(C1)
      M = (C2.x - S.x) mod p (ambil komponen pertama)
    """
    S = _pow_T(C1, k, a, p)
    M0 = (C2[0] - S[0]) % p
    return M0
