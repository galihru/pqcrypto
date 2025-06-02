package com.pelajaran.pqcrypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;

public class LaiCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();

    public static BigInteger H(BigInteger x, BigInteger y, BigInteger s, BigInteger p) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] xBytes = toFixedLength(x);
            byte[] yBytes = toFixedLength(y);
            byte[] sBytes = toFixedLength(s);
            sha.update(xBytes);
            sha.update(yBytes);
            sha.update(sBytes);
            byte[] digest = sha.digest();
            byte[] extended = new byte[digest.length + 1];
            extended[0] = 0x00;
            System.arraycopy(digest, 0, extended, 1, digest.length);
            BigInteger hashBI = new BigInteger(extended);
            return hashBI.mod(p);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static BigInteger sqrtMod(BigInteger a, BigInteger p) {
        a = a.mod(p);
        if (a.equals(BigInteger.ZERO)) return BigInteger.ZERO;
        BigInteger ls = a.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        if (ls.equals(p.subtract(BigInteger.ONE))) return null;
        if (p.testBit(1)) {
            return a.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        }
        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (q.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            q = q.shiftRight(1);
            s++;
        }
        BigInteger z = BigInteger.TWO;
        while (z.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p)
                .equals(BigInteger.ONE)) {
            z = z.add(BigInteger.ONE);
        }
        BigInteger m = BigInteger.valueOf(s);
        BigInteger c = z.modPow(q, p);
        BigInteger t = a.modPow(q, p);
        BigInteger r = a.modPow(q.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        while (!t.equals(BigInteger.ONE)) {
            BigInteger t2i = t;
            int i = 0;
            for (; i < m.intValue(); i++) {
                t2i = t2i.modPow(BigInteger.TWO, p);
                if (t2i.equals(BigInteger.ONE)) break;
            }
            BigInteger b = c.modPow(BigInteger.TWO.pow(m.intValue() - i - 1), p);
            m = BigInteger.valueOf(i);
            c = b.modPow(BigInteger.TWO, p);
            t = t.multiply(c).mod(p);
            r = r.multiply(b).mod(p);
        }
        return r;
    }

    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        return a.modInverse(m);
    }

    public static Point T(Point P, BigInteger s, BigInteger a, BigInteger p) {
        BigInteger x = P.x, y = P.y;
        BigInteger h = H(x, y, s, p);
        BigInteger inv2 = modInverse(BigInteger.valueOf(2), p);
        BigInteger xNew = x.add(a).add(h).multiply(inv2).mod(p);
        BigInteger y_sq = x.multiply(y).add(h).mod(p);
        BigInteger yNew = sqrtMod(y_sq, p);
        if (yNew == null) {
            throw new IllegalStateException(
                String.format("No sqrt for %s mod %s", y_sq.toString(), p.toString()));
        }
        return new Point(xNew, yNew);
    }

    public static Point powT(Point P, BigInteger startS, BigInteger exp, BigInteger a, BigInteger p) {
        Point result = new Point(P.x, P.y);
        Point base = new Point(P.x, P.y);
        BigInteger k = exp;
        BigInteger s = startS;
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) {
                result = T(result, s, a, p);
            }
            base = T(base, s, a, p);
            k = k.shiftRight(1);
            s = s.add(BigInteger.ONE);
        }
        return result;
    }

    public static KeyPair keyGen(BigInteger p, BigInteger a, Point P0) {
        BigInteger k;
        do {
            k = new BigInteger(p.bitLength(), RANDOM);
        } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(p.subtract(BigInteger.ONE)) > 0);
        Point Q = powT(P0, BigInteger.ONE, k, a, p);
        return new KeyPair(k, Q);
    }

    public static Ciphertext encrypt(BigInteger m, Point Q, BigInteger p, BigInteger a, Point P0) {
        BigInteger r;
        do {
            r = new BigInteger(p.bitLength(), RANDOM);
        } while (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(p.subtract(BigInteger.ONE)) > 0);

        Point C1 = powT(P0, BigInteger.ONE, r, a, p);
        Point Sr = powT(Q, BigInteger.ONE, r, a, p);
        BigInteger mRed = m.mod(p);
        Point M = new Point(mRed, BigInteger.ZERO);
        BigInteger c2x = M.x.add(Sr.x).mod(p);
        BigInteger c2y = M.y.add(Sr.y).mod(p);
        Point C2 = new Point(c2x, c2y);
        return new Ciphertext(C1, C2, r);
    }

    public static BigInteger decrypt(Point C1, Point C2, BigInteger k, BigInteger r, BigInteger a, BigInteger p) {
        Point S = powT(C1, r.add(BigInteger.ONE), k, a, p);
        BigInteger m = C2.x.subtract(S.x).mod(p);
        return m;
    }

    public static byte[] decryptAll(JsonNode laiData) {
        BigInteger p = new BigInteger(laiData.get("p").asText());
        BigInteger a = new BigInteger(laiData.get("a").asText());
        JsonNode P0node = laiData.get("P0");
        Point P0 = new Point(
            new BigInteger(P0node.get(0).asText()),
            new BigInteger(P0node.get(1).asText())
        );
        BigInteger k = new BigInteger(laiData.get("k").asText());
        JsonNode blocks = laiData.get("blocks");

        int bitLen = p.bitLength();
        int B = (bitLen - 1) / 8;
        if (B < 1) {
            throw new IllegalArgumentException("Prime p too small for any byte.");
        }

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        for (Iterator<JsonNode> it = blocks.elements(); it.hasNext(); ) {
            JsonNode blk = it.next();
            JsonNode C1n = blk.get("C1");
            JsonNode C2n = blk.get("C2");
            BigInteger x1 = new BigInteger(C1n.get(0).asText());
            BigInteger y1 = new BigInteger(C1n.get(1).asText());
            BigInteger x2 = new BigInteger(C2n.get(0).asText());
            BigInteger y2 = new BigInteger(C2n.get(1).asText());
            BigInteger rBlock = new BigInteger(blk.get("r").asText());

            Point C1 = new Point(x1, y1);
            Point C2 = new Point(x2, y2);
            BigInteger M_int = decrypt(C1, C2, k, rBlock, a, p);

            byte[] rawLE = M_int.toByteArray();
            if (rawLE.length > 1 && rawLE[rawLE.length - 1] == 0x00) {
                byte[] tmp = new byte[rawLE.length - 1];
                System.arraycopy(rawLE, 0, tmp, 0, tmp.length);
                rawLE = tmp;
            }
            if (rawLE.length > B) {
                throw new IllegalStateException(
                    String.format("Integer block %s too large (length %d > %d).",
                                  M_int.toString(), rawLE.length, B)
                );
            }
            byte[] paddedLE = new byte[B];
            System.arraycopy(rawLE, 0, paddedLE, 0, rawLE.length);
            for (int i = 0; i < B/2; i++) {
                byte tmp = paddedLE[i];
                paddedLE[i] = paddedLE[B - 1 - i];
                paddedLE[B - 1 - i] = tmp;
            }
            baos.writeBytes(paddedLE);
        }
        return baos.toByteArray();
    }

    private static byte[] toFixedLength(BigInteger x) {
        byte[] raw = x.toByteArray();
        if (raw.length > 1 && raw[0] == 0x00) {
            byte[] tmp = new byte[raw.length - 1];
            System.arraycopy(raw, 1, tmp, 0, tmp.length);
            raw = tmp;
        }
        return raw;
    }

    public static class Point {
        public final BigInteger x, y;
        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }
    public static class KeyPair {
        public final BigInteger k;
        public final Point Q;
        public KeyPair(BigInteger k, Point Q) {
            this.k = k;
            this.Q = Q;
        }
    }
    public static class Ciphertext {
        public final Point C1, C2;
        public final BigInteger r;
        public Ciphertext(Point C1, Point C2, BigInteger r) {
            this.C1 = C1;
            this.C2 = C2;
            this.r = r;
        }
    }

    public static void main(String[] args) throws Exception {
        BigInteger p = BigInteger.valueOf(10007);
        BigInteger a = BigInteger.valueOf(5);
        Point P0 = new Point(BigInteger.ONE, BigInteger.ZERO);

        KeyPair kp = keyGen(p, a, P0);
        System.out.println("Private k: " + kp.k);
        System.out.println("Public Q: (" + kp.Q.x + ", " + kp.Q.y + ")");

        BigInteger message = BigInteger.valueOf(2024);
        Ciphertext ct = encrypt(message, kp.Q, p, a, P0);
        System.out.println("C1: (" + ct.C1.x + ", " + ct.C1.y + ")");
        System.out.println("C2: (" + ct.C2.x + ", " + ct.C2.y + ")");
        System.out.println("r:  " + ct.r);

        BigInteger recovered = decrypt(ct.C1, ct.C2, kp.k, ct.r, a, p);
        System.out.println("Recovered: " + recovered);
        if (!recovered.equals(message)) {
            throw new IllegalStateException("Decryption mismatch!");
        }
        System.out.println("Round-trip successful.");
    }
}
