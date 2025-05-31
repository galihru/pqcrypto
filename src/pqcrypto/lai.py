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

        # Jika gagal, naikkan seed dan coba lagi
        s_current += 1
        trials += 1

    raise ValueError(
        f"T: Gagal menemukan sqrt untuk y^2={y_sq} mod {p} setelah {trials} percobaan."
    )


def _pow_T_range(P: Tuple[int, int], start_s: int, exp: int, a: int, p: int) -> Tuple[int, int]:
    """
    Terapkan T secara berurutan 'exp' kali, 
    dengan seed index mulai di 'start_s', 'start_s+1', ..., 'start_s+exp-1':

      result = P
      for i in 0 .. exp-1:
          result = T(result, start_s + i)

    Return T^exp(P) dengan seed tepat.
    """
    result = P
    curr_s = start_s
    for _ in range(exp):
        result = T(result, curr_s, a, p)
        curr_s += 1
    return result


def keygen(p: int, a: int, P0: Tuple[int, int]) -> Tuple[int, Tuple[int, int]]:
    """
    Generasi kunci:
      1. Pilih k random di [1, p-1].
      2. Hitung Q = T^k(P0) dengan seed index 1..k.
      3. Jika gagal, ulangi dengan k baru.
      Return (k, Q).
    """
    while True:
        k = secrets.randbelow(p - 1) + 1
        try:
            # Seeds 1..k
            Q = _pow_T_range(P0, start_s=1, exp=k, a=a, p=p)
            return k, Q
        except ValueError:
            continue  # gagal → coba k lain


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
      2. C1 = T^r(P0) dengan seed 1..r.
         Jika gagal, ulangi dengan r baru.
      3. Sr = T^r(Q) dengan seed (k+1)..(k+r).
         Jika gagal, ulangi dengan r baru.
      4. M = (m mod p, 0).
      5. C2 = M + Sr  (penjumlahan komponen).
      Return (C1, C2).
    """
    while True:
        r = secrets.randbelow(p - 1) + 1

        # Hitung C1 = T^r(P0), seeds 1..r
        try:
            C1 = _pow_T_range(P0, start_s=1, exp=r, a=a, p=p)
        except ValueError:
            continue  # coba r baru

        # Hitung Sr = T^r(public_Q), seeds (k+1)..(k+r)
        # Kita butuh k dari public_Q; namun public_Q dihitung dg seed 1..k
        # Jadi kapan pembuatan public_Q dilakukan, kita simpan k
        # Untuk keperluan encrypt(), public_Q seharusnya sudah dibuat dengan keygen() and k diketahui.

        # Sebagai trik: kita harus mengoper k ke encrypt()
        # => ubah signature encrypt() menjadi encrypt(m, public_Q, k, p, a, P0)

        raise NotImplementedError(
            "Signature encrypt() perlu parameter 'k' agar dapat menggunakan seed yang benar."
        )


def decrypt(
    C1: Tuple[int, int],
    C2: Tuple[int, int],
    k: int,
    a: int,
    p: int,
) -> int:
    """
    Dekripsi:
      S = T^k(C1) dengan seed (r+1)..(r+k).
      M = (C2.x - S.x) mod p
      Return komponen pertama M.
      Jika gagal, melempar ValueError.
    """
    # Sama catatan: perlu mengetahui r agar seed benar
    raise NotImplementedError(
        "Signature decrypt() perlu parameter 'r' agar dapat menggunakan seed yang benar."
    )
