//! Lemniscate-AGM Isogeny (LAI) Encryption Engine
//!
//! Quantum‐Resistant Cryptography via Lemniscate Lattices and AGM Transformations.
//!
//! # Features
//! - Key Generation
//! - Public Key Derivation
//! - Deterministic T-transform
//! - Message Encryption / Decryption
//! - Traceable Steps for Audit / Research

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// All known errors from LAI operations
#[derive(Debug)]
pub enum LaiCryptoError {
    /// Gagal menghitung akar kuadrat modular (Tonelli-Shanks)
    SqrtFailure {
        attempts: u32,
        input: u128,
        modulus: u128,
    },
    /// Transformasi T gagal walaupun sudah 10 percobaan
    TransformFailure {
        point: (u128, u128),
        s: u128,
    },
    /// Keygen tidak dapat menyelesaikan T
    KeygenFailed,
}

/// Output hasil transformasi satu langkah
#[derive(Debug, Clone)]
pub struct TraceStep {
    pub step: u128,
    pub s: u128,
    pub h: u128,
    pub x1: u128,
    pub y2: u128,
    pub y1: Option<u128>,
}

/// Mesin LAI encryption
pub struct LaiCryptoEngine {
    pub p: u128,
    pub a: u128,
    pub p0: (u128, u128),
    pub trace: Vec<TraceStep>,
}

impl LaiCryptoEngine {
    pub fn new(p: u128, a: u128, p0: (u128, u128)) -> Self {
        Self {
            p,
            a,
            p0,
            trace: Vec::new(),
        }
    }

    pub fn mod_pow(&self, mut base: u128, mut exp: u128) -> u128 {
        let m = self.p;
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

    pub fn sqrt_mod(&self, a: u128) -> Option<u128> {
        let a = a % self.p;
        if a == 0 {
            return Some(0);
        }
        if self.mod_pow(a, (self.p - 1) / 2) == self.p - 1 {
            return None;
        }
        if self.p % 4 == 3 {
            return Some(self.mod_pow(a, (self.p + 1) / 4));
        }

        let mut q = self.p - 1;
        let mut s = 0;
        while q % 2 == 0 {
            q /= 2;
            s += 1;
        }

        let mut z = 2;
        while self.mod_pow(z, (self.p - 1) / 2) != self.p - 1 {
            z += 1;
        }

        let mut m = s;
        let mut c = self.mod_pow(z, q);
        let mut t = self.mod_pow(a, q);
        let mut r = self.mod_pow(a, (q + 1) / 2);

        while t != 1 {
            let mut i = 1;
            let mut t2i = self.mod_pow(t, 2);
            while t2i != 1 && i < m {
                t2i = self.mod_pow(t2i, 2);
                i += 1;
            }
            if i == m {
                return None;
            }

            let b = self.mod_pow(c, 1 << (m - i - 1));
            m = i;
            c = (b * b) % self.p;
            t = (t * c) % self.p;
            r = (r * b) % self.p;
        }
        Some(r)
    }

    /// Hash function for T transformation
    pub fn h(&self, x: u128, y: u128, s: u128) -> u128 {
        let mut hasher = Sha256::new();
        hasher.update(x.to_string());
        hasher.update(b"|");
        hasher.update(y.to_string());
        hasher.update(b"|");
        hasher.update(s.to_string());
        let digest = hasher.finalize();
        let mut res = 0u128;
        for &b in digest.iter() {
            res = (res << 8) | b as u128;
        }
        res % self.p
    }

    /// Transformasi satu langkah
    pub fn t(&mut self, point: (u128, u128), s: u128) -> Result<(u128, u128), LaiCryptoError> {
        let (x, y) = point;
        let inv2 = self.mod_pow(2, self.p - 2);
        let mut s_cur = s;

        for i in 0..10 {
            let hh = self.h(x, y, s_cur);
            let x1 = ((x + self.a + hh) * inv2) % self.p;
            let y2 = (x * y + hh) % self.p;
            let y1 = self.sqrt_mod(y2);
            self.trace.push(TraceStep {
                step: i,
                s: s_cur,
                h: hh,
                x1,
                y2,
                y1,
            });
            if let Some(y1_val) = y1 {
                return Ok((x1, y1_val));
            }
            s_cur += 1;
        }
        Err(LaiCryptoError::TransformFailure { point, s })
    }

    /// Aplikasi T sebanyak `exp` kali mulai dari `start_s`
    pub fn pow_t_range(
        &mut self,
        mut point: (u128, u128),
        start_s: u128,
        exp: u128,
    ) -> Result<(u128, u128), LaiCryptoError> {
        let mut s = start_s;
        for _ in 0..exp {
            point = self.t(point, s)?;
            s += 1;
        }
        Ok(point)
    }

    pub fn keygen(&mut self) -> Result<(u128, (u128, u128)), LaiCryptoError> {
        for _ in 0..100 {
            let mut buf = [0u8; 16];
            OsRng.fill_bytes(&mut buf);
            let k = u128::from_be_bytes(buf) % (self.p - 1) + 1;
            if let Ok(q) = self.pow_t_range(self.p0, 1, k) {
                return Ok((k, q));
            }
        }
        Err(LaiCryptoError::KeygenFailed)
    }

    pub fn encrypt(
        &mut self,
        m: u128,
        q: (u128, u128),
        k: u128,
    ) -> Result<((u128, u128), (u128, u128), u128), LaiCryptoError> {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        let r = u128::from_be_bytes(buf) % (self.p - 1) + 1;

        let c1 = self.pow_t_range(self.p0, 1, r)?;
        let sr = self.pow_t_range(q, 1, r)?;
        let c2 = ((m + sr.0) % self.p, sr.1);
        Ok((c1, c2, r))
    }

    pub fn decrypt(
        &mut self,
        c1: (u128, u128),
        c2: (u128, u128),
        k: u128,
    ) -> Result<u128, LaiCryptoError> {
        let s_val = self.pow_t_range(c1, 1, k)?;
        Ok((c2.0 + self.p - s_val.0) % self.p)
    }

    /// Menampilkan jejak transformasi
    pub fn print_trace(&self) {
        println!("=== Trace T Transformation ===");
        for step in &self.trace {
            println!(
                "[{}] s = {}, h = {}, x' = {}, y² = {}, y = {:?}",
                step.step, step.s, step.h, step.x1, step.y2, step.y1
            );
        }
    }
}
