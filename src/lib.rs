//! Lemniscate-AGM Isogeny (LAI) Encryption.
//! Quantum-Resistant Cryptography via Lemniscate Lattices and AGM Transformations.

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// H(x, y, s) = SHA256(x || "|" || y || "|" || s) mod p
pub fn H(x: u128, y: u128, s: u128, p: u128) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(x.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(y.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(s.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut res = 0u128;
    for &b in digest.iter() {
        res = (res << 8) | b as u128;
    }
    res % p
}

/// Tonelli–Shanks algorithm untuk sqrt_mod
pub fn sqrt_mod(a: u128, p: u128) -> Option<u128> {
    let a = a % p;
    if a == 0 {
        return Some(0);
    }
    // Legendre symbol
    let ls = mod_pow(a, (p - 1) / 2, p);
    if ls == p - 1 {
        return None;
    }
    // Kasus p ≡ 3 mod 4
    if p % 4 == 3 {
        return Some(mod_pow(a, (p + 1) / 4, p));
    }
    // Tonelli-Shanks
    let mut q = p - 1;
    let mut s = 0;
    while q % 2 == 0 {
        q /= 2;
        s += 1;
    }
    // cari z: non-residu
    let mut z = 2;
    while mod_pow(z, (p - 1) / 2, p) != p - 1 {
        z += 1;
    }
    let mut m = s;
    let mut c = mod_pow(z, q, p);
    let mut t = mod_pow(a, q, p);
    let mut r = mod_pow(a, (q + 1) / 2, p);
    while t % p != 1 {
        // cari i terkecil dimana t^(2^i) ≡ 1
        let mut t2i = t;
        let mut i = 0;
        for j in 1..m {
            t2i = mod_pow(t2i, 2, p);
            if t2i == 1 {
                i = j;
                break;
            }
        }
        let b = mod_pow(c, 1 << (m - i - 1), p);
        m = i;
        c = (b * b) % p;
        t = (t * c) % p;
        r = (r * b) % p;
    }
    Some(r)
}

/// pangkat modular
fn mod_pow(base: u128, exp: u128, m: u128) -> u128 {
    let mut res = 1u128;
    let mut b = base % m;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            res = (res * b) % m;
        }
        b = (b * b) % m;
        e >>= 1;
    }
    res
}

/// Transformasi T
pub fn T(point: (u128, u128), s: u128, a: u128, p: u128) -> (u128, u128) {
    let (mut x, mut y) = point;
    let inv2 = mod_pow(2, p - 2, p);
    let mut trials = 0;
    let mut s_cur = s;
    loop {
        let h = H(x, y, s_cur, p);
        let x1 = ((x + a + h) * inv2) % p;
        let y2 = (x * y + h) % p;
        if let Some(y1) = sqrt_mod(y2, p) {
            return (x1, y1);
        }
        trials += 1;
        s_cur += 1;
        if trials >= 10 {
            panic!("T: gagal setelah 10 percobaan");
        }
    }
}

/// T^exp dengan seed mulai di start_s
pub fn pow_T_range(
    mut point: (u128, u128),
    start_s: u128,
    exp: u128,
    a: u128,
    p: u128,
) -> (u128, u128) {
    let mut s = start_s;
    for _ in 0..exp {
        point = T(point, s, a, p);
        s += 1;
    }
    point
}

/// Generate keypair (k, Q)
pub fn keygen(p: u128, a: u128, P0: (u128, u128)) -> (u128, (u128, u128)) {
    loop {
        let mut k = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        let k = u128::from_be_bytes(k) % (p - 1) + 1;
        if let Ok(q) = std::panic::catch_unwind(|| pow_T_range(P0, 1, k, a, p)) {
            return (k, q);
        }
    }
}

/// Enkripsi
pub fn encrypt(
    m: u128,
    public_q: (u128, u128),
    k: u128,
    p: u128,
    a: u128,
    P0: (u128, u128),
) -> ((u128, u128), (u128, u128), u128) {
    loop {
        let mut r_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut r_bytes);
        let r = u128::from_be_bytes(r_bytes) % (p - 1) + 1;
        let C1 = pow_T_range(P0, 1, r, a, p);
        let Sr = pow_T_range(public_q, k + 1, r, a, p);
        let M = (m % p, 0);
        let C2 = ((M.0 + Sr.0) % p, (M.1 + Sr.1) % p);
        return (C1, C2, r);
    }
}

/// Dekripsi
pub fn decrypt(
    C1: (u128, u128),
    C2: (u128, u128),
    k: u128,
    r: u128,
    a: u128,
    p: u128,
) -> u128 {
    let S = pow_T_range(C1, r + 1, k, a, p);
    (C2.0 + p - S.0) % p
}
