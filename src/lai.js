/**
 * src/lai.js
 *
 * Porting dari python version (lai.py) → implementasi JavaScript (Node.js) menggunakan BigInt
 * Lemniscate-AGM Isogeny (LAI) Encryption.
 * Quantum-Resistant Cryptography via Lemniscate Lattices dan AGM Transformations.
 */

const crypto = require('crypto');

/**
 * H(x, y, s, p) = SHA-256(x || y || s) mod p
 * Non-linear seed untuk setiap iterasi.
 * Gunakan BigInt untuk operasi modulo
 * 
 * @param {BigInt} x
 * @param {BigInt} y
 * @param {BigInt|number} s  — nilai seed (bisa BigInt atau number)
 * @param {BigInt} p
 * @returns {BigInt} hasil SHA-256 mod p
 */
function H(x, y, s, p) {
  // Gabungkan x | y | s menjadi string, kemudian encode UTF-8
  const data = Buffer.from(`${x.toString()}|${y.toString()}|${s.toString()}`, 'utf8');
  const hash = crypto.createHash('sha256').update(data).digest();
  // hash adalah Buffer 32 byte; ubah ke BigInt
  const digestBigInt = BigInt('0x' + hash.toString('hex'));
  return digestBigInt % p;
}

/**
 * Tonelli-Shanks untuk mencari sqrt_mod(a, p), p prime.
 * Jika tidak ada akar (a bukan kuadrat residu), kembalikan null.
 * 
 * @param {BigInt} a
 * @param {BigInt} p
 * @returns {BigInt|null} sqrt_mod atau null jika gagal
 */
function sqrt_mod(a, p) {
  a = ((a % p) + p) % p;
  if (a === 0n) return 0n;

  // Hitung Legendre symbol: a^((p-1)//2) mod p
  const ls = modPow(a, (p - 1n) / 2n, p);
  if (ls === p - 1n) {
    // Non-residu → tidak ada akar
    return null;
  }

  // Kasus cepat jika p % 4 === 3
  if (p % 4n === 3n) {
    return modPow(a, (p + 1n) / 4n, p);
  }

  // Tonelli-Shanks untuk p ≡ 1 (mod 4)
  let q = p - 1n;
  let s = 0n;
  while (q % 2n === 0n) {
    q /= 2n;
    s += 1n;
  }

  // Cari z: kuadrat non-residu
  let z = 2n;
  while (modPow(z, (p - 1n) / 2n, p) !== p - 1n) {
    z += 1n;
  }

  let m = s;
  let c = modPow(z, q, p);
  let t = modPow(a, q, p);
  let r = modPow(a, (q + 1n) / 2n, p);

  while (true) {
    if (t === 1n) {
      return r;
    }
    // Cari i terkecil: t^(2^i) ≡ 1 mod p
    let t2i = t;
    let i = 0n;
    for (let j = 1n; j < m; j++) {
      t2i = (t2i * t2i) % p;
      if (t2i === 1n) {
        i = j;
        break;
      }
    }
    // b = c^(2^(m-i-1))
    const b = modPow(c, 1n << (m - i - 1n), p);
    m = i;
    c = (b * b) % p;
    t = (t * c) % p;
    r = (r * b) % p;
  }
}

/**
 * Fungsi modular exponentiation: base^exp mod mod
 * Semua parameter BigInt.
 * 
 * @param {BigInt} base
 * @param {BigInt} exp
 * @param {BigInt} mod
 * @returns {BigInt}
 */
function modPow(base, exp, mod) {
  if (exp < 0n) throw new Error('Eksponen negatif tidak didukung');
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * Transformasi T(point, s, a, p):
 *   x' = (x + a + H(x,y,s)) * inv2 mod p
 *   y' = sqrt_mod(x*y + H(x,y,s), p)
 * Jika sqrt_mod gagal, naikkan s hingga 10 kali.
 * 
 * @param {[BigInt, BigInt]} point  — [x, y]
 * @param {BigInt} s_seed
 * @param {BigInt} a
 * @param {BigInt} p
 * @returns {[BigInt, BigInt]}
 */
function T(point, s_seed, a, p) {
  let [x, y] = point;
  const inv2 = modPow(2n, p - 2n, p); // invers dari 2 mod p
  let trials = 0;
  let s_current = s_seed;

  while (trials < 10) {
    const h = H(x, y, s_current, p);
    const x_candidate = ((x + a + h) * inv2) % p;
    const y_sq = (x * y + h) % p;
    const y_candidate = sqrt_mod(y_sq, p);
    if (y_candidate !== null) {
      return [x_candidate, y_candidate];
    }
    s_current += 1n;
    trials += 1;
  }
  throw new Error(`T: Gagal menemukan sqrt untuk y^2 mod p setelah ${trials} percobaan.`);
}

/**
 * _pow_T_range(P, start_s, exp, a, p):
 *   Terapkan T secara berurutan 'exp' kali, dengan seed mulai di 'start_s'
 * 
 * @param {[BigInt, BigInt]} P   — titik awal [x, y]
 * @param {BigInt} start_s       — seed index pertama
 * @param {BigInt} exp           — jumlah iterasi
 * @param {BigInt} a
 * @param {BigInt} p
 * @returns {[BigInt, BigInt]}
 */
function _pow_T_range(P, start_s, exp, a, p) {
  let result = P;
  let curr_s = start_s;
  for (let i = 0n; i < exp; i++) {
    result = T(result, curr_s, a, p);
    curr_s += 1n;
  }
  return result;
}

/**
 * keygen(p, a, P0):
 *   1. Pilih k random di [1, p-1].
 *   2. Q = T^k(P0) dengan seed index 1..k.
 *   Jika gagal, ulangi.
 * @param {BigInt} p
 * @param {BigInt} a
 * @param {[BigInt, BigInt]} P0
 * @returns {{ k: BigInt, Q: [BigInt, BigInt] }}
 */
function keygen(p, a, P0) {
  while (true) {
    // Pilih k random di [1, p-1]
    // Kita bisa generate raw bytes panjang cukup untuk mewakili p,
    // lalu mod (p-1) + 1. Untuk kesederhanaan, gunakan metode berikut:
    const randomBytes = crypto.randomBytes(p.toString(16).length / 2 + 1);
    let kCandidate = BigInt('0x' + randomBytes.toString('hex')) % (p - 1n);
    kCandidate = kCandidate + 1n; // pastikan >= 1

    try {
      const Q = _pow_T_range(P0, 1n, kCandidate, a, p);
      return { k: kCandidate, Q };
    } catch (e) {
      // Jika gagal (ValueError di Python, Error di sini), ulangi
      continue;
    }
  }
}

/**
 * encrypt(m, public_Q, k, p, a, P0):
 *   1. Pilih r random di [1, p-1].
 *   2. C1 = T^r(P0) dengan seed 1..r
 *   3. Sr = T^r(public_Q) dengan seed (k+1)..(k+r)
 *   4. M = (m mod p, 0)
 *   5. C2 = M + Sr (komponen-wise mod p)
 * @param {BigInt} m
 * @param {[BigInt, BigInt]} public_Q
 * @param {BigInt} k
 * @param {BigInt} p
 * @param {BigInt} a
 * @param {[BigInt, BigInt]} P0
 * @returns {{ C1: [BigInt, BigInt], C2: [BigInt, BigInt], r: BigInt }}
 */
function encrypt(m, public_Q, k, p, a, P0) {
  while (true) {
    // Pilih r random
    const randomBytesR = crypto.randomBytes(p.toString(16).length / 2 + 1);
    let r = BigInt('0x' + randomBytesR.toString('hex')) % (p - 1n);
    r = r + 1n;

    // 2. C1 = T^r(P0), seed 1..r
    let C1;
    try {
      C1 = _pow_T_range(P0, 1n, r, a, p);
    } catch (e) {
      continue;
    }

    // 3. Sr = T^r(public_Q), seed (k+1)..(k+r)
    let Sr;
    try {
      Sr = _pow_T_range(public_Q, k + 1n, r, a, p);
    } catch (e) {
      continue;
    }

    // 4. M = (m mod p, 0)
    const M0 = m % p;
    const M = [M0 < 0n ? M0 + p : M0, 0n];

    // 5. C2 = M + Sr (mod p)
    const C2x = (M[0] + Sr[0]) % p;
    const C2y = (M[1] + Sr[1]) % p;
    return { C1, C2: [C2x, C2y], r };
  }
}

/**
 * decrypt(C1, C2, k, r, a, p):
 *   1. S = T^k(C1) dengan seed (r+1)..(r+k)
 *   2. M0 = (C2.x - S.x) mod p
 *   Return M0 (BigInt)
 * @param {[BigInt, BigInt]} C1
 * @param {[BigInt, BigInt]} C2
 * @param {BigInt} k
 * @param {BigInt} r
 * @param {BigInt} a
 * @param {BigInt} p
 * @returns {BigInt}
 */
function decrypt(C1, C2, k, r, a, p) {
  const S = _pow_T_range(C1, r + 1n, k, a, p);
  const M0 = (C2[0] - S[0]) % p;
  return M0 < 0n ? M0 + p : M0;
}

module.exports = {
  H,
  sqrt_mod,
  T,
  _pow_T_range,
  keygen,
  encrypt,
  decrypt,
};
