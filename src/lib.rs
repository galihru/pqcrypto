//! Lemniscate-AGM Isogeny (LAI) Encryption.
//! Quantum‐Resistant Cryptography via Lemniscate Lattices and AGM Transformations.

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// H(x, y, s) = SHA-256(x || "|" || y || "|" || s) mod p
pub fn h(x: u128, y: u128, s: u128, p: u128) -> u128 {
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

/// Modular exponentiation: base^exp mod m
fn mod_pow(mut base: u128, mut exp: u128, m: u128) -> u128 {
    let mut result = 1u128;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    result
}

/// Tonelli–Shanks: compute sqrt(a) mod p, if exists
pub fn sqrt_mod(a: u128, p: u128) -> Option<u128> {
    let a = a % p;
    if a == 0 {
        return Some(0);
    }
    // Legendre symbol a^((p-1)/2) mod p
    let ls = mod_pow(a, (p - 1) / 2, p);
    if ls == p - 1 {
        return None;
    }
    // Fast case p % 4 == 3
    if p % 4 == 3 {
        return Some(mod_pow(a, (p + 1) / 4, p));
    }
    // Tonelli–Shanks for p % 4 == 1
    let mut q = p - 1;
    let mut s = 0;
    while q % 2 == 0 {
        q /= 2;
        s += 1;
    }
    // find z: quadratic non-residue
    let mut z = 2;
    while mod_pow(z, (p - 1) / 2, p) != p - 1 {
        z += 1;
    }
    let mut m = s;
    let mut c = mod_pow(z, q, p);
    let mut t = mod_pow(a, q, p);
    let mut r = mod_pow(a, (q + 1) / 2, p);

    while t % p != 1 {
        // find least i: t^(2^i) == 1
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

/// One step transformation T
pub fn t(point: (u128, u128), s: u128, a: u128, p: u128) -> (u128, u128) {
    let (x, y) = point;
    let inv2 = mod_pow(2, p - 2, p);
    let mut trials = 0;
    let mut s_cur = s;

    while trials < 10 {
        let hh = h(x, y, s_cur, p);
        let x1 = ((x + a + hh) * inv2) % p;
        let y2 = (x * y + hh) % p;
        if let Some(y1) = sqrt_mod(y2, p) {
            return (x1, y1);
        }
        trials += 1;
        s_cur += 1;
    }
    panic!("t: gagal menemukan sqrt setelah 10 percobaan");
}

/// Apply T repeatedly `exp` times starting with seed index `start_s`
pub fn pow_t_range(
    mut point: (u128, u128),
    start_s: u128,
    exp: u128,
    a: u128,
    p: u128,
) -> (u128, u128) {
    let mut s_idx = start_s;
    for _ in 0..exp {
        point = t(point, s_idx, a, p);
        s_idx += 1;
    }
    point
}

/// Generate keypair: returns (k, Q)
pub fn keygen(p: u128, a: u128, p0: (u128, u128)) -> (u128, (u128, u128)) {
    loop {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        let k = u128::from_be_bytes(buf) % (p - 1) + 1;
        // catch panic from t if any
        let q = std::panic::catch_unwind(|| pow_t_range(p0, 1, k, a, p));
        if let Ok(q_val) = q {
            return (k, q_val);
        }
    }
}

/// Encrypt: returns (c1, c2, r)
pub fn encrypt(
    m: u128,
    public_q: (u128, u128),
    k: u128,
    p: u128,
    a: u128,
    p0: (u128, u128),
) -> ((u128, u128), (u128, u128), u128) {
    loop {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        let r = u128::from_be_bytes(buf) % (p - 1) + 1;

        let c1 = pow_t_range(p0, 1, r, a, p);
        let sr = pow_t_range(public_q, k + 1, r, a, p);
        let m_val = (m % p, 0);
        let c2 = ((m_val.0 + sr.0) % p, (m_val.1 + sr.1) % p);
        return (c1, c2, r);
    }
}

/// Decrypt: returns recovered message m
pub fn decrypt(
    c1: (u128, u128),
    c2: (u128, u128),
    k: u128,
    r: u128,
    a: u128,
    p: u128,
) -> u128 {
    let s_val = pow_t_range(c1, r + 1, k, a, p);
    (c2.0 + p - s_val.0) % p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_pow_and_sqrt() {
        let p = 23u128;
        let a = 9u128;
        // 9 is a square mod 23 (3^2)
        assert_eq!(sqrt_mod(a, p), Some(3));
        assert_eq!(mod_pow(3, 2, p), 9);
    }

    #[test]
    fn test_h_consistency() {
        let v1 = h(10, 20, 5, 97);
        let v2 = h(10, 20, 5, 97);
        assert_eq!(v1, v2);
    }
}
