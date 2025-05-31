"""
lai.py

Lemniscate-AGM Isogeny (LAI) Encryption.
Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations.
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
    a = a % p
    if a == 0:
        return 0

    # Legendre symbol: a^((p-1)//2) mod p
    ls = pow(a, (p - 1) // 2, p)
    if ls == p - 1:
        # Non-residu → tidak ada akar kuadrat
        return None

    # Kasus cepat jika p ≡ 3 (mod 4)
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Tonelli–Shanks untuk p ≡ 1 (mod 4)
    # Tulis p-1 = q * 2^s, dengan q ganjil
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
        # Cari i terkecil: t^(2^i) ≡ 1 (mod p)
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
      x' = (x + a + H(x,y,s)) * inv2  mod p
      y' = sqrt_mod(x*y + H(x,y,s), p)

    Jika sqrt_mod gagal (None), naikkan s (fallback) hingga 10 kali.
    Lemniscate‐AGM Isogeny step.
    """
    x, y = point
    inv2 = pow(2, p - 2, p)  # invers dari 2 mod p

    trials = 0
    s_current = s

    # Coba hingga 10 kali dengan seed index yang meningkat
    while trials < 10:
        h = H(x, y, s_current, p)
        x_candidate = ((x + a + h) * inv2) % p
        y_sq = (x * y + h) % p
        y_candidate = sqrt_mod(y_sq, p)
        if y_candidate is not None:
            return x_candidate, y_candidate

        # Jika gagal, naikkan seed dan ulangi
        s_current += 1
        trials += 1

    raise ValueError(
        f"T: Gagal menemukan sqrt untuk y^2={y_sq} mod {p} setelah {trials} percobaan."
    )


def _pow_T_sequential(P: Tuple[int, int], exp: int, a: int, p: int) -> Tuple[int, int]:
    """
    Terapkan T sebanyak 'exp' kali secara berurutan,
    dengan seed index mulai 1,2,...,exp:
      T^exp(P) = T(T(...T(P,1)..., exp-1), exp).

    Kompleksitas O(exp), sesuai definisi matematis LAI.
    """
    result = P
    for i in range(1, exp + 1):
        result = T(result, i, a, p)
    return result


def keygen(p: int, a: int, P0: Tuple[int, int]) -> Tuple[int, Tuple[int, int]]:
    """
    Generasi kunci:
      1. Pilih k random di [1, p-1].
      2. Hitung Q = T^k(P0) (aplikasi berurutan).
      3. Jika gagal (ValueError), ulangi dengan k baru.
      Return (k, Q).
    """
    while True:
        k = secrets.randbelow(p - 1) + 1
        try:
            Q = _pow_T_sequential(P0, k, a, p)
            return k, Q
        except ValueError:
            # T^k(P0) gagal → pilih k baru
            continue


def encrypt(
    m: int,
    public_Q: Tuple[int, int],
    p: int,
    a: int,
    P0: Tuple[int, int],
) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Enkripsi:
      1. Pilih r random di [1, p-1].
      2. C1 = T^r(P0).
         Jika T^r(P0) gagal, ulangi dengan r baru.
      3. Sr = T^r(public_Q).
         Jika T^r(public_Q) gagal, ulangi dengan r baru.
      4. M = (m mod p, 0).
      5. C2 = M + Sr  (penjumlahan komponen).
      Return (C1, C2).
    """
    while True:
        r = secrets.randbelow(p - 1) + 1

        # Hitung C1 = T^r(P0)
        try:
            C1 = _pow_T_sequential(P0, r, a, p)
        except ValueError:
            # Gagal, coba r baru
            continue

        # Hitung Sr = T^r(public_Q)
        try:
            Sr = _pow_T_sequential(public_Q, r, a, p)
        except ValueError:
            # Gagal, coba r baru
            continue

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
      M = (C2.x - S.x) mod p
      Return komponen pertama M.
      Jika T^k(C1) gagal, melempar ValueError.
    """
    S = _pow_T_sequential(C1, k, a, p)  # Bisa melempar ValueError
    M0 = (C2[0] - S[0]) % p
    return M0
