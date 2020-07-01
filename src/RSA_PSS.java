import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * RSA-PSS数字签名方案
 */
public class RSA_PSS {
    /**
     * hash函数输出字节长度
     */
    public final static int H_LEN = 20;
    /**
     * 盐的字节长度
     */
    public final static int S_LEN = 20;

    /**
     * 掩码生成函数，基于SHA-1
     *
     * @param x       被掩码的字节串
     * @param maskLen 掩码的字节长度
     * @return 长度为maskLen字节的掩码
     */
    public static byte[] MGF(byte[] x, int maskLen) {
        byte[] mask = new byte[maskLen];
        // 初始化变量
        byte[] t = new byte[0];
        int k = maskLen % H_LEN == 0 ? maskLen / H_LEN - 1 : maskLen / H_LEN;
        // hash函数的输入
        byte[] hashInput = new byte[x.length + 4];
        // 前面始终是x
        System.arraycopy(x, 0, hashInput, 0, x.length);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            for (int i = 0; i <= k; i++) {
                // hash函数的输入后4字节为i
                System.arraycopy(intToBytes(i), 0, hashInput, x.length, 4);
                // hash值Hash(x||i)
                messageDigest.update(hashInput);
                byte[] tmp = new byte[t.length + H_LEN];
                // t=t||Hash(x||i)
                System.arraycopy(t, 0, tmp, 0, t.length);
                System.arraycopy(messageDigest.digest(), 0, tmp, 0, H_LEN);
                t = tmp;
            }
            // mask为t的前maskLen字节
            System.arraycopy(t, 0, mask, 0, maskLen);
            return mask;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return mask;
    }

    /**
     * 消息编码
     *
     * @param m      用于签名的待编码消息
     * @param emBits 比RSA模数n的长度小
     * @return 编码后的消息
     */
    private static byte[] encode(BigInteger m, int emBits) {
        // em的字节长度
        int emLen = emBits % 8 == 0 ? emBits / 8 : emBits / 8 + 1;
        byte[] em = new byte[emLen];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            // m的hash值
            byte[] mHash = messageDigest.digest();
            // 随机生成的S_LEN字节作为盐，此处长度可能小于S_LEN字节
            byte[] salt = toByteArray(new BigInteger(8 * S_LEN, new SecureRandom()));
            // m'=paddind1||mHash||salt，padding1为8字节全零串
            byte[] m2 = new byte[8 + H_LEN + S_LEN];
            System.arraycopy(mHash, 0, m2, 8, H_LEN);
            // ！！！salt的长度不确定，填充时要注意
            System.arraycopy(salt, 0, m2, 8 + H_LEN + S_LEN - salt.length, salt.length);
            messageDigest.update(m2);
            // m'的hash值
            byte[] h = messageDigest.digest();
            // db=padding2||salt，padding2为emLen -S_LEN-H_LEN-2个00加01
            byte[] db = new byte[emLen - H_LEN - 1];
            db[emLen - S_LEN - H_LEN - 2] = 1;
            // ！！！salt的长度不确定，填充时要注意
            System.arraycopy(salt, 0, db, emLen - H_LEN - 1 - salt.length, salt.length);
            // dbMask=MGF(h, emLen - H_LEN - 1)
            byte[] dbMask = MGF(h, emLen - H_LEN - 1);
            byte[] maskedDB = xor(db, dbMask);
            // maskedDB的最左字节的左8 * emLen - emBits位设为0
            maskedDB[0] = (byte) (maskedDB[0] & (0xff >> (8 * emLen - emBits)));
            // em=maskDB||h||0xbc
            System.arraycopy(maskedDB, 0, em, 0, emLen - H_LEN - 1);
            System.arraycopy(h, 0, em, emLen - H_LEN - 1, H_LEN);
            em[emLen - 1] = (byte) 0xbc;
            return em;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return em;
    }

    /**
     * 生成签名
     *
     * @param em 编码后的消息
     * @param d  RSA私钥d
     * @param n  RSA模数n
     * @return 签名字节串
     */
    public static byte[] sign(byte[] em, BigInteger d, BigInteger n) {
        // em转为无符号整数
        BigInteger m = new BigInteger(1, em);
        BigInteger s = m.modPow(d, n);
        return toByteArray(s);
    }

    /**
     * 签名解密
     *
     * @param s 签名
     * @param e RSA公钥e
     * @param n RSA模数n
     * @return 解密后的消息em
     */
    private static byte[] decode(byte[] s, BigInteger e, BigInteger n) {
        BigInteger s2 = new BigInteger(1, s);
        BigInteger m = s2.modPow(e, n);
        return toByteArray(m);
    }

    /**
     * em验证
     *
     * @param m      待验证消息
     * @param em1    签名解密后的字节串
     * @param emBits 比RSA模数n的长度小
     * @return 签名是否合法
     */
    public static boolean verify(BigInteger m, byte[] em1, int emBits) {
        // em的长度
        int emLen = emBits % 8 == 0 ? emBits / 8 : emBits / 8 + 1;
        byte[] em = new byte[emLen];
        if(em1.length>emLen)
            return false;
        // em的前几个字节可能为0，解密时会去掉，所以要将em1补充完整
        System.arraycopy(em1, 0, em, emLen - em1.length, em1.length);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(toByteArray(m));
            // m的hash值
            byte[] mHsah = messageDigest.digest();
            // 先检查长度
            if (emLen < H_LEN + S_LEN + 2)
                return false;
            // em的最右字节应为0xbc
            if (em[emLen - 1] != (byte) (0xbc))
                return false;
            // maskedDB等于em的左emLen - H_LEN - 1字节
            byte[] maskedDB = new byte[emLen - H_LEN - 1];
            System.arraycopy(em, 0, maskedDB, 0, emLen - H_LEN - 1);
            // h为接下来的H_LEN字节
            byte[] h = new byte[H_LEN];
            System.arraycopy(em, emLen - H_LEN - 1, h, 0, H_LEN);
            // maskedDB的最左字节的左8 * emLen + emBits应全为0
            if (maskedDB[0] >> (8 - 8 * emLen + emBits) != 0)
                return false;
            byte[] dbMask = MGF(h, emLen - H_LEN - 1);
            byte[] db = xor(maskedDB, dbMask);
            // 设置db的最左字节的左8 * emLen + emBits全为0
            db[0] = (byte) (db[0] & (0xff >> (8 * emLen - emBits)));
            // db的最左emLen - H_LEN - S_LEN-1字节应等于padding2
            for (int i = 0; i < emLen - H_LEN - S_LEN - 2; i++)
                if (db[i] != 0)
                    return false;
            if (db[emLen - H_LEN - S_LEN - 2] != 1)
                return false;
            byte[] salt = new byte[S_LEN];
            // db的最后S_LEN字节设置为盐
            System.arraycopy(db, emLen - H_LEN - S_LEN - 1, salt, 0, S_LEN);
            // m'=padding1||mHash||salt
            byte[] m2 = new byte[8 + H_LEN + S_LEN];
            System.arraycopy(mHsah, 0, m2, 8, H_LEN);
            System.arraycopy(salt, 0, m2, 8 + H_LEN, S_LEN);
            messageDigest.update(m2);
            // h'Hash(m')
            byte[] h2 = messageDigest.digest();
            // 如果h=h'则签名合法
            if (Arrays.equals(h, h2)) {
                return true;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * int转4字节
     */
    private static byte[] intToBytes(int counter) {
        byte[] b = new byte[4];
        b[3] = (byte) (counter & 0xff);
        b[2] = (byte) ((counter >> 8) & 0xff);
        b[1] = (byte) ((counter >> 16) & 0xff);
        b[0] = (byte) ((counter >> 24) & 0xff);
        return b;
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

    /**
     * byte数组异或
     */
    private static byte[] xor(byte[] a, byte[] b) {
        int len = a.length;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = (byte) (a[i] ^ b[i]);
        return result;
    }

    public static void main(String[] args) {
        // BigInteger m = new BigInteger("12345");
        // byte[] em = encode(m, 500);
        // BigInteger d = new
        // BigInteger("1184462294782087337998708010004602054418342278755225457707629191050942318489279853161588200617005892945079139440986167400267558338604354233448681129014074306248071562237506851069799");
        // BigInteger n = new
        // BigInteger("2722431650402441591841302017562053144200465420156337775950693526778261967354236691012954788359757829817596771734732625209000217134580512972201755512239700834344229450855685834240383");
        // byte[] s = sign(em, d, n);
        // BigInteger e = new
        // BigInteger("2645504498536272610247327117804038630432078360751607982747692424737749827631617979178906230195876979189303372356831481198781252857056187273029734439353593238421511022685133348164727");
        // byte[] em2 = decode(s, e, n);
        // System.out.println(verify(m, em2, 500));
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. sign\n2. verify");
        int op = scanner.nextInt();
        System.out.print("message: ");
        BigInteger m = new BigInteger(scanner.next());
        if (op == 1) {
            System.out.print("emBits: ");
            int emBits = scanner.nextInt();
            byte[] em = encode(m, emBits);
            System.out.print("RSA d: ");
            BigInteger d = new BigInteger(scanner.next());
            System.out.print("RSA n: ");
            BigInteger n = new BigInteger(scanner.next());
            System.out.print("s: " + new BigInteger(1, sign(em, d, n)).toString());
        } else {
            System.out.print("s: ");
            BigInteger s = new BigInteger(scanner.next());
            System.out.print("emBits: ");
            int emBits = scanner.nextInt();
            System.out.print("RSA e: ");
            BigInteger e = new BigInteger(scanner.next());
            System.out.print("RSA n: ");
            BigInteger n = new BigInteger(scanner.next());
            byte[] em = decode(toByteArray(s), e, n);
            System.out.print(verify(m, em, emBits));
        }
        scanner.close();
    }
}
