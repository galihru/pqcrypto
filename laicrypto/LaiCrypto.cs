using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;

namespace PQCrypto
{
    public static class LaiCrypto
    {
        public static BigInteger H(BigInteger x, BigInteger y, BigInteger s, BigInteger p)
        {
            string data = $"{x}|{y}|{s}";
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            byte[] hash;
            using (SHA256 sha = SHA256.Create())
            {
                hash = sha.ComputeHash(bytes);
            }
            byte[] tmp = new byte[hash.Length + 1];
            for (int i = 0; i < hash.Length; i++)
            {
                tmp[i] = hash[hash.Length - 1 - i];
            }
            tmp[tmp.Length - 1] = 0x00;

            BigInteger hashBig = new BigInteger(tmp);
            return BigInteger.Remainder(hashBig, p);
        }
        public static BigInteger ModPow(BigInteger baseValue, BigInteger exp, BigInteger mod)
        {
            return BigInteger.ModPow(baseValue, exp, mod);
        }
        private static BigInteger LegendreSymbol(BigInteger a, BigInteger p)
        {
            return BigInteger.ModPow(a, (p - 1) / 2, p);
        }
        public static BigInteger? SqrtMod(BigInteger a_in, BigInteger p_in)
        {
            BigInteger a = ((a_in % p_in) + p_in) % p_in;
            if (a.IsZero) return 0;

            BigInteger ls = LegendreSymbol(a, p_in);
            if (ls == p_in - 1) 
            {
                return null; // tidak ada akar
            }
            if ((p_in % 4) == 3)
            {
                return BigInteger.ModPow(a, (p_in + 1) / 4, p_in);
            }
            BigInteger q = p_in - 1;
            BigInteger s = 0;
            while ((q & 1) == 0)
            {
                q >>= 1;
                s++;
            }
            BigInteger z = 2;
            while (LegendreSymbol(z, p_in) != p_in - 1)
            {
                z++;
            }
            BigInteger m = s;
            BigInteger c = BigInteger.ModPow(z, q, p_in);
            BigInteger t = BigInteger.ModPow(a, q, p_in);
            BigInteger r = BigInteger.ModPow(a, (q + 1) / 2, p_in);

            while (t != 1)
            {
                BigInteger t2i = t;
                BigInteger i = 0;
                for (BigInteger j = 1; j < m; j++)
                {
                    t2i = BigInteger.ModPow(t2i, 2, p_in);
                    if (t2i == 1)
                    {
                        i = j;
                        break;
                    }
                }
                BigInteger b = BigInteger.ModPow(c, BigInteger.Pow(2, (int)(m - i - 1)), p_in);
                m = i;
                c = BigInteger.ModPow(b, 2, p_in);
                t = (t * c) % p_in;
                r = (r * b) % p_in;
            }
            return r;
        }
        public static (BigInteger X, BigInteger Y) T((BigInteger X, BigInteger Y) point, BigInteger s, BigInteger a, BigInteger p)
        {
            BigInteger x = point.X;
            BigInteger y = point.Y;
            BigInteger h = H(x, y, s, p);
            BigInteger inv2 = ModInverse(2, p);
            BigInteger xNew = BigInteger.Multiply(BigInteger.Add(BigInteger.Add(x, a), h), inv2) % p;

            BigInteger ySq = (x * y + h) % p;
            BigInteger? yNew = SqrtMod(ySq, p);
            if (yNew == null)
            {
                throw new Exception($"T: Gagal menemukan sqrt untuk y^2={ySq} mod {p}");
            }
            return (xNew, yNew.Value);
        }
        public static BigInteger ModInverse(BigInteger value, BigInteger mod)
        {
            BigInteger a = value % mod;
            if (a < 0) a += mod;
            BigInteger m = mod;
            BigInteger m0 = m, y = 0, x = 1;

            if (m == 1) return 0;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }

            if (x < 0) x += m0;
            return x;
        }
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
        public static BigInteger DecryptBlock((BigInteger X, BigInteger Y) C1, (BigInteger X, BigInteger Y) C2, BigInteger k, BigInteger r, BigInteger a, BigInteger p)
        {
            // seeds mulai dari r+1 hingga r+k
            var S = PowT(C1, r + 1, (int)k, a, p);
            BigInteger M = (C2.X - S.X + p) % p;
            return M;
        }
        public static byte[] DecryptAll(dynamic laiData)
        {
            BigInteger p = (BigInteger)laiData.p;
            BigInteger a = (BigInteger)laiData.a;
            BigInteger k = (BigInteger)laiData.k;

            int bitLen = (int)Math.Floor(BigInteger.Log(p, 2)) + 1;
            int B = (bitLen - 1) / 8;

            var blocks = (IEnumerable<dynamic>)laiData.blocks;

            using (var ms = new System.IO.MemoryStream())
            {
                foreach (var blk in blocks)
                {
                    BigInteger x1 = (BigInteger)blk.C1[0];
                    BigInteger y1 = (BigInteger)blk.C1[1];
                    BigInteger x2 = (BigInteger)blk.C2[0];
                    BigInteger y2 = (BigInteger)blk.C2[1];
                    BigInteger r = (BigInteger)blk.r;

                    var M_int = DecryptBlock((x1, y1), (x2, y2), k, r, a, p);

                    byte[] mBytesLittle = M_int.ToByteArray(); 
                    var mBytesLE = mBytesLittle;
                    if (mBytesLE.Length > 1 && mBytesLE[mBytesLE.Length - 1] == 0x00)
                    {
                        // Pastikan byte ini hasil sign extension, bukan data
                        byte[] tmp = new byte[mBytesLE.Length - 1];
                        Array.Copy(mBytesLE, tmp, tmp.Length);
                        mBytesLE = tmp;
                    }
                    if (mBytesLE.Length > B)
                    {
                        throw new Exception($"Blok integer {M_int} lebih besar daripada p memungkinkan (mBytesLE.Length={mBytesLE.Length} > B={B}).");
                    }
                    byte[] paddedLE = new byte[B];
                    Array.Copy(mBytesLE, 0, paddedLE, 0, mBytesLE.Length);
                    byte[] chunkBE = paddedLE.Reverse().ToArray();

                    ms.Write(chunkBE, 0, chunkBE.Length);
                }
                return ms.ToArray();
            }
        }
    }
}
