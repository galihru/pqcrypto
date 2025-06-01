using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PQCrypto
{
    /// <summary>
    /// Contoh implementasi sederhana Lemniscate-AGM Isogeny (LAI) di C#.
    /// Port logika T_js, sqrt_mod, H, decrypt_block, decrypt_all_text dari JS/Python.
    /// Ini hanya skeleton: Anda harus mengisi implementasi lengkap sesuai algoritma.
    /// </summary>
    public static class LaiCrypto
    {
        // Fungsi H(x,y,s) = SHA256($"{x}|{y}|{s}") mod p
        public static BigInteger H(BigInteger x, BigInteger y, BigInteger s, BigInteger p)
        {
            string data = $"{x}|{y}|{s}";
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bytes);
                BigInteger hashBig = new BigInteger(hash, isUnsigned: true, isBigEndian: true);
                return hashBig % p;
            }
        }

        // Modular exponentiation: base^exp mod m
        public static BigInteger ModPow(BigInteger baseValue, BigInteger exp, BigInteger mod)
        {
            return BigInteger.ModPow(baseValue, exp, mod);
        }

        // Tonelli–Shanks untuk sqrt_mod(a,p). Jika gagal, lempar exception atau return null.
        public static BigInteger? SqrtMod(BigInteger a, BigInteger p)
        {
            a = (a % p + p) % p;
            if (a.IsZero) return 0;
            // Legendre symbol: a^{(p-1)/2} mod p
            BigInteger ls = BigInteger.ModPow(a, (p - 1) / 2, p);
            if (ls == p - 1) return null;
            if (p % 4 == 3)
            {
                return BigInteger.ModPow(a, (p + 1) / 4, p);
            }
            // Tonelli-Shanks untuk p ≡ 1 mod 4 (implementasi lengkap diperlukan)
            throw new NotImplementedException("Tonelli-Shanks for generic p belum diimplementasi.");
        }

        // Transformasi T(x,y; s)
        public static (BigInteger X, BigInteger Y) T((BigInteger X, BigInteger Y) point, BigInteger s, BigInteger a, BigInteger p)
        {
            BigInteger x = point.X, y = point.Y;
            BigInteger h = H(x, y, s, p);
            BigInteger inv2 = ModInverse(2, p);
            BigInteger xNew = ((x + a + h) * inv2) % p;
            BigInteger ySq = (x * y + h) % p;
            BigInteger? yNew = SqrtMod(ySq, p);
            if (yNew == null)
            {
                throw new Exception($"T: sqrt tidak ditemukan untuk y^2={ySq} mod {p}");
            }
            return (xNew, yNew.Value);
        }

        // Extended Euclidean untuk inverse mod
        public static BigInteger ModInverse(BigInteger value, BigInteger mod)
        {
            BigInteger a = value % mod, m = mod;
            if (a < 0) a += m;
            BigInteger m0 = m, y = 0, x = 1;
            if (m == 1) return 0;
            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;
                m = a % m; a = t;
                t = y;
                y = x - q * y;
                x = t;
            }
            if (x < 0) x += m0;
            return x;
        }

        // _pow_T_range: terapkan T() sebanyak exp kali dengan seed mulai startS
        public static (BigInteger X, BigInteger Y) PowT((BigInteger X, BigInteger Y) P, BigInteger startS, int exp, BigInteger a, BigInteger p)
        {
            var result = P;
            var s = startS;
            for (int i = 0; i < exp; i++)
            {
                result = T(result, s, a, p);
                s += 1;
            }
            return result;
        }

        /// <summary>
        /// Dekripsi satu blok (C1, C2, k, r, a, p) → BigInteger M
        /// </summary>
        public static BigInteger DecryptBlock((BigInteger, BigInteger) C1, (BigInteger, BigInteger) C2, BigInteger k, BigInteger r, BigInteger a, BigInteger p)
        {
            var S = PowT(C1, r + 1, (int)k, a, p);  // seeds mulai r+1 … r+k
            BigInteger M = (C2.Item1 - S.Item1 + p) % p;
            return M;
        }

        /// <summary>
        /// Decrypt all blocks dan gabungkan menjadi byte[] yang mewakili teks JS asli
        /// </summary>
        public static byte[] DecryptAll(dynamic laiData)
        {
            // laiData berbentuk dynamic atau class khusus yang memuat p,a,P0,k,Q, dan blocks: List of {C1:[x,y], C2:[x,y], r}
            BigInteger p = laiData.p;
            BigInteger a = laiData.a;
            BigInteger k = laiData.k;
            int B; // ukuran byte per blok
            {
                int bit_len = p.ToString(2).Length;
                B = (bit_len - 1) / 8;
            }
            var blocks = laiData.blocks; // enumerable

            using (var ms = new System.IO.MemoryStream())
            {
                foreach (var blk in blocks)
                {
                    BigInteger x1 = blk.C1[0], y1 = blk.C1[1];
                    BigInteger x2 = blk.C2[0], y2 = blk.C2[1];
                    BigInteger r = blk.r;
                    var M_int = DecryptBlock((x1, y1), (x2, y2), k, r, a, p);
                    // Konversi M_int ke array bytes panjang B (big-endian)
                    var bytes = M_int.ToByteArray(isUnsigned: true, isBigEndian: true);
                    // Jika panjang < B, pad di depan dengan 0
                    if (bytes.Length < B)
                    {
                        var tmp = new byte[B];
                        Array.Copy(bytes, 0, tmp, B - bytes.Length, bytes.Length);
                        bytes = tmp;
                    }
                    ms.Write(bytes, 0, bytes.Length);
                }
                return ms.ToArray();
            }
        }
    }
}
