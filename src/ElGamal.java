import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

/**
 * ElGamal数字签名方案
 */
public class ElGamal {
    /**
     * 产生公私钥
     *
     * @param qLen 素数q的位数
     * @param aLen 原根g的位数
     * @return q, a，私钥X，公钥Y
     */
    public static BigInteger[] generateKey(int qLen, int aLen) {
        BigInteger[] g = generator(qLen, aLen);
        BigInteger q = g[0];
        BigInteger a = g[1];
        SecureRandom secureRandom = new SecureRandom();
        BigInteger x = new BigInteger(q.bitLength(), secureRandom);
        // 1<X<q-1
        while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) >= 0)
            x = new BigInteger(q.bitLength(), secureRandom);
        // Y=a^X mod q
        BigInteger y = a.modPow(x, q);
        return new BigInteger[]{q, a, x, y};
    }

    /**
     * 签名
     *
     * @param m 消息
     * @param q 公钥q
     * @param a 公钥a
     * @param x 私钥X
     * @return 签名S1，S2
     */
    public static BigInteger[] sign(BigInteger m, BigInteger q, BigInteger a, BigInteger x) {
        BigInteger[] s = new BigInteger[2];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            BigInteger hash = new BigInteger(1, messageDigest.digest());
            // 0<=hash<=q-1
            if (hash.compareTo(BigInteger.ZERO) < 0 || hash.compareTo(q) >= 0)
                throw new IllegalArgumentException();
            SecureRandom secureRandom = new SecureRandom();
            BigInteger k = new BigInteger(q.bitLength(), secureRandom);
            // 1<=K<=q-1且gcd(K,q-1)=1
            while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(q) >= 0
                    || !k.gcd(q.subtract(BigInteger.ONE)).equals(BigInteger.ONE))
                k = new BigInteger(q.bitLength(), secureRandom);
            // S1=a^k mod q
            s[0] = a.modPow(k, q);
            BigInteger invK = k.modInverse(q.subtract(BigInteger.ONE));
            // S2=K^(-1) * (hash-X*S1) mod(q-1)
            s[1] = invK.multiply(hash.subtract(x.multiply(s[0]))).mod(q.subtract(BigInteger.ONE));
            return s;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return s;
    }

    /**
     * 验证签名
     *
     * @param m         消息
     * @param signature 签名
     * @param q         公钥q
     * @param a         公钥a
     * @param y         公钥Y
     * @return 签名是否合法
     */
    public static boolean verify(BigInteger m, BigInteger[] signature, BigInteger q, BigInteger a, BigInteger y) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            BigInteger hash = new BigInteger(1, messageDigest.digest());
            // V1=a^hash mod q
            BigInteger v1 = a.modPow(hash, q);
            // V2=y^S1 * S1^S2 mod q
            BigInteger v2 = y.modPow(signature[0], q).multiply(signature[0].modPow(signature[1], q)).mod(q);
            // V1=V2则签名合法
            return v1.equals(v2);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 产生素数及其原根
     *
     * @param pLen 素数位数
     * @param gLen 原根位数
     * @return 素数p，原根g
     */
    public static BigInteger[] generator(int pLen, int gLen) {
        Random rnd = new Random();
        BigInteger p, q, g, x, y;
        do {
            q = BigInteger.probablePrime(pLen, rnd);
            p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!p.isProbablePrime((int) (0.7 * pLen)));

        do {
            g = BigInteger.probablePrime(gLen, rnd);
            x = g.multiply(g).mod(p);
            y = g.modPow(q, p);
        } while (x.equals(BigInteger.ONE) || y.equals(BigInteger.ONE));
        return new BigInteger[]{p, g};
    }


    /**
     * BigInteger转byte[]，去掉符号位0
     */
    private static byte[] toByteArray(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b[0] == 0) {
            byte[] result = new byte[b.length - 1];
            System.arraycopy(b, 1, result, 0, result.length);
            return result;
        } else
            return b;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. sign\n2. verify");
        int op = scanner.nextInt();
        System.out.print("message: ");
        BigInteger m = new BigInteger(scanner.next());
        if (op == 1) {
            System.out.print("length of q: ");
            int qLen = scanner.nextInt();
            System.out.print("length of α: ");
            int aLen = scanner.nextInt();
            BigInteger[] key = generateKey(qLen, aLen);
            System.out.println("q: " + key[0]);
            System.out.println("α: " + key[1]);
            System.out.println("X: " + key[2]);
            System.out.println("Y: " + key[3]);
            BigInteger[] s = sign(m, key[0], key[1], key[2]);
            System.out.println("S1: " + s[0]);
            System.out.println("S2: " + s[1]);
        } else {
            BigInteger[] s = new BigInteger[2];
            System.out.print("S1: ");
            s[0] = new BigInteger(scanner.next());
            System.out.print("S2: ");
            s[1] = new BigInteger(scanner.next());
            System.out.print("q: ");
            BigInteger q = new BigInteger(scanner.next());
            System.out.print("α: ");
            BigInteger a = new BigInteger(scanner.next());
            System.out.print("y: ");
            BigInteger y = new BigInteger(scanner.next());
            System.out.print(verify(m, s, q, a, y));
        }
        scanner.close();
    }
}
