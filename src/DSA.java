import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class DSA {
    /**
     * 生成密钥
     *
     * @param l p的位数
     * @param n q的位数
     * @return 全局公钥p, q, g，私钥x，公钥y
     */
    private static BigInteger[] generateKey(int l, int n) {
        SecureRandom qRandom = new SecureRandom();
        // q为n为素数
        BigInteger q = BigInteger.probablePrime(n, qRandom);
        while (q.bitLength() != n)
            q = BigInteger.probablePrime(n, qRandom);
        SecureRandom factorRandom = new SecureRandom();
        BigInteger factor = new BigInteger(l - n, factorRandom);
        // p-1=q*factor
        BigInteger p = q.multiply(factor).add(BigInteger.ONE);
        // p为l位素数
        while (p.bitLength() != l || !p.isProbablePrime(7)) {
            factor = new BigInteger(l - n, factorRandom);
            p = q.multiply(factor).add(BigInteger.ONE);
        }
        SecureRandom hRandom = new SecureRandom();
        BigInteger h = new BigInteger(l, hRandom);
        // 1<h<(p-1), h^factor % p > 1
        while (h.compareTo(BigInteger.ONE) <= 0 || h.compareTo(p.subtract(BigInteger.ONE)) >= 0
                || h.modPow(factor, p).compareTo(BigInteger.ONE) <= 0)
            h = new BigInteger(l, hRandom);
        BigInteger g = h.modPow(factor, p);
        SecureRandom xRandom = new SecureRandom();
        BigInteger x = new BigInteger(n, xRandom);
        // 0<x<q
        while (x.equals(BigInteger.ZERO) || x.compareTo(q) >= 0)
            x = new BigInteger(n, xRandom);
        // y=g^x % p
        BigInteger y = g.modPow(x, p);
        return new BigInteger[]{p, q, g, x, y};
    }

    /**
     * 产生下一个k
     *
     * @param q 全局公钥q
     * @return 与每条消息相关的秘密值
     */
    private static BigInteger nextK(BigInteger q) {
        SecureRandom kRandom = new SecureRandom();
        BigInteger k = new BigInteger(q.bitLength(), kRandom);
        // 0<k<q
        while (k.equals(BigInteger.ONE) || k.compareTo(q) >= 0)
            k = new BigInteger(q.bitLength(), kRandom);
        k = new BigInteger("123");
        return k;
    }

    /**
     * 签名
     *
     * @param m 消息
     * @param p 全局公钥p
     * @param q 全局公钥q
     * @param g 全局公钥g
     * @param x 私钥x
     * @return 签名r, s
     */
    public static BigInteger[] sign(BigInteger m, BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
        BigInteger[] signature = new BigInteger[2];
        // 产生k
        BigInteger k = nextK(q);
        // r=g^k % p % q
        BigInteger r = g.modPow(k, p).mod(q);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            BigInteger hashM = new BigInteger(1, messageDigest.digest());
            // s=k^(-1) * (H(m)+xr) % q
            BigInteger s = k.modInverse(q).multiply(hashM.add(x.multiply(r))).mod(q);
            signature[0] = r;
            signature[1] = s;
            return signature;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return signature;
    }

    /**
     * 验证签名
     *
     * @param m 消息
     * @param s 签名r,s
     * @param p 全局公钥p
     * @param q 全局公钥q
     * @param g 全局公钥g
     * @param y 公钥y
     * @return 签名是否合法
     */
    public static boolean verify(BigInteger m, BigInteger[] s, BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        // w=s^(-1) mod q
        BigInteger w = s[1].modInverse(q);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            BigInteger hashM = new BigInteger(1, messageDigest.digest());
            // u1=H(m)*w % q
            BigInteger u1 = hashM.multiply(w).mod(q);
            // u2=rw % q
            BigInteger u2 = s[0].multiply(w).mod(q);
            // v=g^u1 * y^u2 % p % q
            BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
            // 如果v=r则签名合法
            return v.equals(s[0]);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
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
        // BigInteger m = new BigInteger("12345");
        // BigInteger key[] = generateKey(512, 256);
        // BigInteger s[] = sign(m, key[0], key[1], key[2], key[3]);
        // System.out.println(verify(m, s, key[0], key[1], key[2], key[4]));
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. sign\n2. verify");
        int op = scanner.nextInt();
        System.out.print("message: ");
        BigInteger m = new BigInteger(scanner.next());
        if (op == 1) {
            System.out.print("L: ");
            int l = scanner.nextInt();
            System.out.print("N: ");
            int n = scanner.nextInt();
            BigInteger[] key = generateKey(l, n);
            System.out.println("p: " + key[0]);
            System.out.println("q: " + key[1]);
            System.out.println("g: " + key[2]);
            System.out.println("x: " + key[3]);
            System.out.println("y: " + key[4]);
            BigInteger[] s = sign(m, key[0], key[1], key[2], key[3]);
            System.out.println("r: " + s[0]);
            System.out.println("s: " + s[1]);
        } else {
            BigInteger[] s = new BigInteger[2];
            System.out.print("r: ");
            s[0] = new BigInteger(scanner.next());
            System.out.print("s: ");
            s[1] = new BigInteger(scanner.next());
            System.out.print("p: ");
            BigInteger p = new BigInteger(scanner.next());
            System.out.print("q: ");
            BigInteger q = new BigInteger(scanner.next());
            System.out.print("g: ");
            BigInteger g = new BigInteger(scanner.next());
            System.out.print("y: ");
            BigInteger y = new BigInteger(scanner.next());
            System.out.print(verify(m, s, p, q, g, y));
        }
        scanner.close();
    }
}
