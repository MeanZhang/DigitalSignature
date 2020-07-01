import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Schnorr数字签名方案
 */
public class Schnorr {
    /**
     * 产生密钥
     *
     * @return 全局公钥参数α, p, q，私钥s，公钥v
     */
    public static BigInteger[] generateKey() {
        SecureRandom qRandom = new SecureRandom();
        // 160位素数q
        BigInteger q = BigInteger.probablePrime(160, qRandom);
        SecureRandom kRandom = new SecureRandom();
        // p-1=kq
        BigInteger k = new BigInteger(864, kRandom);
        BigInteger p = q.multiply(k).add(BigInteger.ONE);
        // p为1024位素数
        while (!p.isProbablePrime(7)) {
            k = new BigInteger(864, kRandom);
            p = q.multiply(k).add(BigInteger.ONE);
        }
        //x^(p-1)≡1(mod p)
        //而p-1=kq
        //所以(x^k)^q≡1(mod p)
        BigInteger x = new BigInteger(1024, new SecureRandom());
        // α^q≡1(mod p)
        BigInteger a = x.modPow(k, p);
        SecureRandom sRandom = new SecureRandom();
        BigInteger s = new BigInteger(160, sRandom);
        // s为0<s<q的随机数
        while (s.compareTo(q) >= 0)
            s = new BigInteger(160, sRandom);
        BigInteger v = a.modInverse(p).modPow(s, p);
        return new BigInteger[]{a, p, q, s, v};
    }

    /**
     * 签名
     *
     * @param m 消息
     * @param a 全局公钥α
     * @param p 全局公钥p
     * @param q 全局公钥q
     * @param s 私钥s
     * @return 签名e, y
     */
    public static BigInteger[] sign(BigInteger m, BigInteger a, BigInteger p, BigInteger q, BigInteger s) {
        BigInteger[] signature = new BigInteger[2];
        SecureRandom secureRandom = new SecureRandom();
        BigInteger r = new BigInteger(160, secureRandom);
        // r为0<r<q的随机数
        while (r.compareTo(q) >= 0)
            r = new BigInteger(160, secureRandom);
        // x=α^r % p
        BigInteger x = a.modPow(r, p);
        try {
            // hash
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            // hash输入为m||x
            byte[] hashInput = toByteArray(m.shiftLeft(x.bitLength()).add(x));
            messageDigest.update(hashInput);
            // 计算hash值e=H(m||x)
            signature[0] = new BigInteger(1, messageDigest.digest());
            // y=r+se % q
            signature[1] = r.add(s.multiply(signature[0])).mod(q);
            return signature;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return signature;
    }

    /**
     * 验证签名
     *
     * @param m         消息
     * @param signature 签名e,y
     * @param a         全局公钥α
     * @param p         全局公钥p
     * @param v         公钥v
     * @return 签名是否合法
     */
    public static boolean verify(BigInteger m, BigInteger[] signature, BigInteger a, BigInteger p, BigInteger v) {
        // x'=α^y * v^e % p
        BigInteger x = a.modPow(signature[1], p).multiply(v.modPow(signature[0], p)).mod(p);
        try {
            // hash
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            // hash输入为m||x'
            byte[] hashInput = toByteArray(m.shiftLeft(x.bitLength()).add(x));
            messageDigest.update(hashInput);
            // 计算hash=H(m||x')
            BigInteger h = new BigInteger(1, messageDigest.digest());
            // 签名e与hash相同则合法
            return h.equals(signature[0]);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return true;
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
        // BigInteger m = new BigInteger("12345678910");
        // BigInteger[] key = generateKey();
        // BigInteger[] s = sign(m, key[0], key[1], key[2], key[3]);
        // m = new BigInteger("12345678910");
        // System.out.println(verify(m, s, key[0], key[1], key[4]));
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. sign\n2. verify");
        int op = scanner.nextInt();
        System.out.print("message: ");
        BigInteger m = new BigInteger(scanner.next());
        if (op == 1) {
            BigInteger[] key = generateKey();
            System.out.println("α: " + key[0]);
            System.out.println("p: " + key[1]);
            System.out.println("q: " + key[2]);
            System.out.println("s: " + key[3]);
            System.out.println("v: " + key[4]);
            BigInteger[] s = sign(m, key[0], key[1], key[2], key[3]);
            System.out.println("e: " + s[0]);
            System.out.println("y: " + s[1]);
        } else {
            BigInteger[] s = new BigInteger[2];
            System.out.print("e: ");
            s[0] = new BigInteger(scanner.next());
            System.out.print("y: ");
            s[1] = new BigInteger(scanner.next());
            System.out.print("α: ");
            BigInteger a = new BigInteger(scanner.next());
            System.out.print("p: ");
            BigInteger p = new BigInteger(scanner.next());
            System.out.print("v: ");
            BigInteger v = new BigInteger(scanner.next());
            System.out.print(verify(m, s, a, p, v));
        }
        scanner.close();
    }
}
