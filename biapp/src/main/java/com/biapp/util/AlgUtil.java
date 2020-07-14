package com.biapp.util;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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
import aura.data.Ints;

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

        NoPadding("NoPadding"), PKCS1Padding("PKCS1Padding"), OAEPWITHMD5AndMGF1Padding("OAEPWITHMD5AndMGF1Padding"), OAEPWITHSHA1AndMGF1Padding("OAEPWITHSHA1AndMGF1Padding"), OAEPWITHSHA256AndMGF1Padding("OAEPWITHSHA256AndMGF1Padding"), OAEPWITHSHA384AndMGF1Padding("OAEPWITHSHA384AndMGF1Padding"), OAEPWITHSHA512AndMGF1Padding("OAEPWITHSHA512AndMGF1Padding");

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
     * 生成RSA公私钥对
     *
     * @param keyLength
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(keyLength);
            keyPair = keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
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
    public static byte[] encrypt(RSAPublicKey publicKey, AsymmetricPadding padding, byte[] data) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA" + "/" + "None" + "/" + padding);
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
    public static byte[] decrypt(RSAPrivateKey privateKey, AsymmetricPadding padding, byte[] data) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA" + "/" + "None" + "/" + padding);
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

    /**
     * TDES DUKPT IK 衍生
     *
     * @param bdk
     * @param ksn
     * @return
     */
    public static byte[] tdesIK(byte[] bdk, byte[] ksn) {
        //TDES DUKPT 没有24字节密钥
        if (bdk.length != 16) {
            throw new IllegalArgumentException("bdk length error");
        }
        if (ksn.length != 10) {
            throw new IllegalArgumentException("ksn length error");
        }
        byte[] ik;
        byte[] makeEBdk = new byte[]{(byte) 0xC0, (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00, (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00};
        byte[] ksnTmp = Bytes.subBytes(ksn, 0, 8);
        //根据算法需要把原来的80个bit的KSN后21bit清零
        ksnTmp[7] &= 0xE0;
        ik = encrypt(SymmetryAlgorithm.TDES, AlgorithmModel.ECB, SymmetryPadding.ZeroPadding, bdk, null, ksnTmp);
        //bdk与makeEBdk异或
        byte[] xorTmp = Bytes.xor(bdk, makeEBdk);
        xorTmp = encrypt(SymmetryAlgorithm.TDES, AlgorithmModel.ECB, SymmetryPadding.ZeroPadding, xorTmp, null, ksnTmp);
        ik = Bytes.concat(ik, xorTmp);
        return ik;
    }

    /**
     * AES DUKPT IK 衍生
     *
     * @param bdk
     * @param ksn
     * @return
     */
    public static byte[] aesIK(byte[] bdk, byte[] ksn) {
        if (!(bdk.length == 16 || bdk.length == 24 || bdk.length == 32)) {
            throw new IllegalArgumentException("bdk length error");
        }
        if (ksn.length != 12) {
            throw new IllegalArgumentException("ksn length error");
        }
        byte[] ik = null;
        byte[] ksnTmp = Bytes.subBytes(ksn, 0, 8);
        // 衍生数据
        byte[] derivData = new byte[16];
        // set Version ID of the table structure
        derivData[0] = 0x01;
        // set Key Block Counter.1 for first block, 2 for second, etc.
        derivData[1] = 0x01;
        // set Key Usage Indicator
        byte[] keyUsage = new byte[]{(byte) 0x80, 0x01};
        derivData[2] = keyUsage[0];
        derivData[3] = keyUsage[1];
        byte[] algIndi = new byte[2];
        byte[] keyLength = new byte[2];
        int blockNum = 1;
        switch (bdk.length) {
            case 16:
                algIndi[0] = 0x00;
                algIndi[1] = 0x02;
                keyLength[0] = 0x00;
                keyLength[1] = (byte) 0x80;
                blockNum = 1;
                break;
            case 24:
                algIndi[0] = 0x00;
                algIndi[1] = 0x03;
                keyLength[0] = 0x00;
                keyLength[1] = (byte) 0xC0;
                blockNum = 2;
                break;
            case 32:
                algIndi[0] = 0x00;
                algIndi[1] = 0x04;
                keyLength[0] = 0x01;
                keyLength[1] = 0x00;
                blockNum = 3;
                break;
        }
        derivData[4] = algIndi[0];
        derivData[5] = algIndi[1];
        derivData[6] = keyLength[0];
        derivData[7] = keyLength[1];
        System.arraycopy(ksnTmp, 0, derivData, 8, 8);
        for (int i = 0; i < blockNum; i++) {
            byte[] result = encrypt(SymmetryAlgorithm.AES, AlgorithmModel.ECB, SymmetryPadding.ZeroPadding, bdk, null, derivData);
            if (Bytes.isNullOrEmpty(ik)) {
                ik = result;
            } else {
                ik = Bytes.concat(ik, result);
            }
            derivData[1]++;
        }
        return Bytes.subBytes(ik, 0, bdk.length);
    }

    /**
     * KSN+1
     *
     * @param ksn
     * @return
     */
    public static String ksnAdd1(String ksn) {
        String newKsn = "";
        byte[] ksnData = Bytes.fromHexString(ksn);
        if (ksnData.length == 10) {
            byte[] iin = Bytes.subBytes(ksnData, 0, 3);
            byte[] cid = Bytes.subBytes(ksnData, 3, 1);
            byte[] gid = Bytes.subBytes(ksnData, 4, 1);
            StringBuffer did_counter = new StringBuffer();
            did_counter.append(Bytes.toBitString(ksnData[5]));
            did_counter.append(Bytes.toBitString(ksnData[6]));
            did_counter.append(Bytes.toBitString(ksnData[7]));
            did_counter.append(Bytes.toBitString(ksnData[8]));
            did_counter.append(Bytes.toBitString(ksnData[9]));
            String did = did_counter.substring(0, 19);
            if ("1111111111111111111".equals(did)) {
                throw new IllegalArgumentException("ksn is already the largest");
            }
            String counter = did_counter.substring(19);
            int did_value = Integer.parseInt(did, 2);
            did_value++;
            String new_did = Bytes.toBitString(Bytes.fromInt(did_value, 3)).substring(5);
            newKsn = Bytes.toHexString(iin) + Bytes.toHexString(cid) + Bytes.toHexString(gid)
                    + FormatUtil.addHead('0', 10, Long.toHexString(Long.parseLong(new_did + counter, 2))).toUpperCase();
        } else if (ksnData.length == 12) {
            String did = Bytes.toHexString(Bytes.subBytes(ksnData, 4, 4));
            if ("FFFFFFFF".equals(did)) {
                throw new IllegalArgumentException("ksn is already the largest");
            }
            int newDid = Ints.fromByteArray(Bytes.fromHexString(did));
            newDid++;
            String new_did = Bytes.toHexString(Bytes.fromInt(newDid, 4));
            newKsn = Bytes.toHexString(ksnData[0]) + Bytes.toHexString(ksnData[1]) + Bytes.toHexString(ksnData[2])
                    + Bytes.toHexString(ksnData[3]) + new_did + Bytes.toHexString(ksnData[8])
                    + Bytes.toHexString(ksnData[9]) + Bytes.toHexString(ksnData[10]) + Bytes.toHexString(ksnData[11]);
        } else {
            throw new IllegalArgumentException("ksn length error");
        }
        return newKsn;
    }
}