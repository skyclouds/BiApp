package com.biapp.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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
public class AlgUtils {

    /**
     * 非对称算法
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
     * 非对称填充
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
     * RSA加密
     *
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] encrypt(RSAPublicKey publicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
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
     * RSA解密
     *
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
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
}