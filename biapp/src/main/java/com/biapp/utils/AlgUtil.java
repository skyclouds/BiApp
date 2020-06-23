package com.biapp.utils;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import aura.data.Bytes;

/**
 * @author yun
 */
public class AlgUtil {

    /**
     * 对称算法
     */
    public enum SymmetryAlgorithm {

        RC2("RC2"), DES("DES"), TDES("DESede"), AES("AES");

        private String name;

        private SymmetryAlgorithm(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * 算法模式
     */
    public enum AlgorithmModel {

        ECB("ECB"), CBC("CBC"), CFB("CFB"), CTR("CTR"), CTS("CTS"), OFB("OFB"), PCBC("PCBC");

        private String name;

        private AlgorithmModel(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * 对称填充
     */
    public enum SymmetryPadding {

        NoPadding("NoPadding"), ZeroPadding("ZeroPadding"), PKCS5Padding("PKCS5Padding"), ISO10126Padding("ISO10126Padding");

        private String name;

        private SymmetryPadding(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }


    /**
     * 非对称填充
     */
    public enum AsymmetricPadding {

        NoPadding("NoPadding"),PKCS1Padding("PKCS1Padding"),OAEPWITHMD5AndMGF1Padding("OAEPWITHMD5AndMGF1Padding"), OAEPWITHSHA1AndMGF1Padding("OAEPWITHSHA1AndMGF1Padding"), OAEPWITHSHA256AndMGF1Padding("OAEPWITHSHA256AndMGF1Padding"), OAEPWITHSHA384AndMGF1Padding("OAEPWITHSHA384AndMGF1Padding"), OAEPWITHSHA512AndMGF1Padding("OAEPWITHSHA512AndMGF1Padding");

        private String name;

        private AsymmetricPadding(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * 散列算法
     */
    public enum HashAlgorithm {

        MD2("MD2"), MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");

        private String name;

        private HashAlgorithm(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * MAC算法
     */
    public enum MACAlgorithm {

        HmacMD5("HmacMD5"), HmacSHA1("HmacSHA1"), HmacSHA256("HmacSHA256"), HmacSHA384("HmacSHA384"), HmacSHA512("HmacSHA512");

        private String name;

        private MACAlgorithm(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * 加密
     *
     * @param algorithm
     * @param mode
     * @param padding
     * @param key
     * @param iv
     * @param data
     * @return
     */
    public static byte[] encrypt(SymmetryAlgorithm algorithm, AlgorithmModel mode, SymmetryPadding padding, byte[] key,
                                 byte[] iv, byte[] data) {
        try {
            if (padding == SymmetryPadding.ZeroPadding) {
                padding = SymmetryPadding.NoPadding;
                int blockSize = (algorithm == SymmetryAlgorithm.AES) ? 16 : 8;
                if (data.length % blockSize != 0) {
                    int paddingLen = (blockSize - (data.length % blockSize));
                    byte[] paddingData = new byte[paddingLen];
                    data = Bytes.concat(data, paddingData);
                }
            }
            //处理双倍长TDES
            if (algorithm == SymmetryAlgorithm.TDES && key.length == 16) {
                if (mode == AlgorithmModel.ECB) {
                    return encryptBy2DESECBNoPadding(key, data);
                } else if (mode == AlgorithmModel.CBC) {
                    byte[] enc = iv;
                    byte[] result = null;
                    for (int round = 0; round < data.length / 8; round++) {
                        byte[] xor = new byte[8];
                        byte[] tmp = Bytes.subBytes(data, round * 8, 8);
                        for (int j = 0; j < xor.length; j++) {
                            xor[j] = (byte) (enc[j] ^ tmp[j]);
                        }
                        enc = encryptBy2DESECBNoPadding(key, xor);
                        if (result == null) {
                            result = enc;
                        } else {
                            result = Bytes.concat(result, enc);
                        }
                    }
                    return result;
                }
            }
            SecretKeySpec keyspec = new SecretKeySpec(key, algorithm.getName());
            Cipher cipher = Cipher.getInstance(algorithm.getName() + "/" + mode.getName() + "/" + padding.getName());
            if (mode == AlgorithmModel.ECB) {
                cipher.init(Cipher.ENCRYPT_MODE, keyspec);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivParameterSpec);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 双倍长DES ECB NoPadding
     *
     * @param key
     * @param data
     * @return
     */
    private static byte[] encryptBy2DESECBNoPadding(byte[] key, byte[] data) {
        byte[] leftKey = Bytes.subBytes(key, 0, 8);
        byte[] rightKey = Bytes.subBytes(key, 8, 16);
        byte[] step1 = encrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, leftKey, null, data);
        byte[] step2 = decrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, rightKey, null, step1);
        return encrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, leftKey, null, step2);
    }


    /**
     * RSA加密
     *
     * @param publicKey
     * @param padding
     * @param data
     * @return
     */
    public static byte[] encrypt(RSAPublicKey publicKey,AsymmetricPadding padding, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA"+"/"+"ECB"+"/"+padding);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param algorithm
     * @param key
     * @param iv
     * @param data
     * @return
     */
    public static byte[] decrypt(SymmetryAlgorithm algorithm, AlgorithmModel mode, SymmetryPadding padding, byte[] key,
                                 byte[] iv, byte[] data) {
        try {
            if (padding == SymmetryPadding.ZeroPadding) {
                padding = SymmetryPadding.NoPadding;
            }
            //处理双倍长TDES
            if (algorithm == SymmetryAlgorithm.TDES && key.length == 16) {
                if (mode == AlgorithmModel.ECB) {
                    return decryptBy2DESECBNoPadding(key, data);
                } else if (mode == AlgorithmModel.CBC) {
                    byte[] enc = iv;
                    byte[] result = null;
                    for (int round = 0; round < data.length / 8; round++) {
                        byte[] tmp = Bytes.subBytes(data, round * 8, 8);
                        byte[] dec = decryptBy2DESECBNoPadding(key, tmp);
                        byte[] xor = new byte[8];
                        for (int j = 0; j < xor.length; j++) {
                            xor[j] = (byte) (enc[j] ^ dec[j]);
                        }
                        enc = tmp;
                        if (result == null) {
                            result = xor;
                        } else {
                            result = Bytes.concat(result, xor);
                        }
                    }
                    return result;
                }
            }
            SecretKeySpec keyspec = new SecretKeySpec(key, algorithm.getName());
            Cipher cipher = Cipher.getInstance(algorithm.getName() + "/" + mode.getName() + "/" + padding.getName());
            if (mode == AlgorithmModel.ECB) {
                cipher.init(Cipher.DECRYPT_MODE, keyspec);
            } else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keyspec, ivParameterSpec);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 双倍长DES ECB NoPadding
     *
     * @param key
     * @param data
     * @return
     */
    private static byte[] decryptBy2DESECBNoPadding(byte[] key, byte[] data) {
        byte[] leftKey = Bytes.subBytes(key, 0, 8);
        byte[] rightKey = Bytes.subBytes(key, 8, 16);
        byte[] step1 = decrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, leftKey, null, data);
        byte[] step2 = encrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, rightKey, null, step1);
        return decrypt(SymmetryAlgorithm.DES, AlgorithmModel.ECB, SymmetryPadding.NoPadding, leftKey, null, step2);
    }

    /**
     * RSA解密
     *
     * @param privateKey
     * @param padding
     * @param data
     * @return
     */
    public static byte[] decrypt(RSAPrivateKey privateKey,AsymmetricPadding padding, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA"+"/"+"ECB"+"/"+padding);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 散列
     *
     * @param algorithm
     * @param data
     * @return
     */
    public static byte[] hash(HashAlgorithm algorithm, byte[] data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm.getName());
            messageDigest.update(data);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * MAC
     *
     * @param algorithm
     * @param key
     * @param data
     * @return
     */
    public static byte[] mac(MACAlgorithm algorithm, byte[] key, byte[] data) {
        try {
            SecretKeySpec keyspec = new SecretKeySpec(key, algorithm.getName());
            Mac mac = Mac.getInstance(algorithm.getName());
            mac.init(keyspec);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获得随机数
     *
     * @param len
     * @return
     */
    public static byte[] getRandom(int len) {
        byte[] random = new byte[len];
        for (int i = 0; i < random.length; i++) {
            int value = (int) (Math.random() * 15);
            char data = (char) value;
            random[i] = (byte) data;
        }
        return random;
    }

    /**
     * @param key
     * @return
     */
    public static byte[] tdesKCV(byte[] key) {
        byte[] zero = new byte[8];
        Arrays.fill(zero, (byte) 0x00);
        return encrypt(SymmetryAlgorithm.TDES, AlgorithmModel.CBC, SymmetryPadding.ZeroPadding, key, zero, zero);
    }

    /**
     * 计算KCV
     *
     * @param key
     * @return
     */
    public static byte[] aesKCV(byte[] key) {
        byte[] zero = new byte[16];
        Arrays.fill(zero, (byte) 0x00);
        return aesCMAC(key, zero);
    }

    /**
     * TDES MCAC
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] tdesCMAC(byte[] key, byte[] data) {
        byte[] cmac = new byte[8];
        BlockCipher cipher = new DESedeEngine();
        org.bouncycastle.crypto.Mac mac = new CMac(cipher, 64);
        CipherParameters params = new KeyParameter(key);
        mac.init(params);
        mac.update(data, 0, data.length);
        mac.doFinal(cmac, 0);
        return cmac;
    }

    /**
     * AES MCAC
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] aesCMAC(byte[] key, byte[] data) {
        byte[] cmac = new byte[16];
        BlockCipher cipher = new AESEngine();
        org.bouncycastle.crypto.Mac mac = new CMac(cipher, 128);
        CipherParameters params = new KeyParameter(key);
        mac.init(params);
        mac.update(data, 0, data.length);
        mac.doFinal(cmac, 0);
        return cmac;
    }
}