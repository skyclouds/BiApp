package com.biapp.util;

import com.biapp.key.KeyAlgorithm;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import aura.data.Bytes;
import aura.data.Ints;
import aura.data.Strings;

/**
 * @author yun
 */
public class AlgUtil {

    // 增加BouncyCastle
    private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        // remove BC provider first
        Security.removeProvider("BC");
        Security.insertProviderAt(BOUNCY_CASTLE_PROVIDER, 0);
    }

    /**
     * 对称算法
     */
    public enum SymmetryAlgorithm {

        DES("DES"),
        TDES("DESede"),
        AES("AES"),
        SM4("SM4");

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
     * 对称模式
     */
    public enum SymmetryModel {

        ECB("ECB"),
        CBC("CBC"),
        CTR("CTR");

        private String name;

        private SymmetryModel(final String name) {
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

        NoPadding("NoPadding"),
        ZeroBytePadding("ZeroBytePadding"),
        PKCS5Padding("PKCS5Padding"),
        PKCS7Padding("PKCS7Padding");

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
     * 加密
     *
     * @param algorithm
     * @param model
     * @param padding
     * @param key
     * @param iv
     * @param data
     * @return
     */
    public static byte[] encrypt(SymmetryAlgorithm algorithm, SymmetryModel model, SymmetryPadding padding, byte[] key,
                                 byte[] iv, byte[] data) {
        try {
            SecretKeySpec keyspec = new SecretKeySpec(key, algorithm.getName());
            Cipher cipher = Cipher.getInstance(algorithm.getName() + "/" + model.getName() + "/" + padding.getName());
            IvParameterSpec ivParameterSpec = null;
            if (iv != null) {
                ivParameterSpec = new IvParameterSpec(iv);
            }
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivParameterSpec);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密
     *
     * @param algorithm
     * @param model
     * @param padding
     * @param key
     * @param iv
     * @param data
     * @return
     */
    public static byte[] decrypt(SymmetryAlgorithm algorithm, SymmetryModel model, SymmetryPadding padding, byte[] key,
                                 byte[] iv, byte[] data) {
        try {
            SecretKeySpec keyspec = new SecretKeySpec(key, algorithm.getName());
            Cipher cipher = Cipher.getInstance(algorithm.getName() + "/" + model.getName() + "/" + padding.getName());
            IvParameterSpec ivParameterSpec = null;
            if (iv != null) {
                ivParameterSpec = new IvParameterSpec(iv);
            }
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivParameterSpec);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 散列算法
     */
    public enum HashAlgorithm {

        SHA256("SHA-256"),
        SHA384("SHA-384"),
        SHA512("SHA-512"),
        SM3("SM3");

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
     * MAC算法填充
     */
    public enum MacAlgorithmPadding {
        Method1, Method2, Method3;
    }

    /**
     * ISO9797-1 Padding Method 1
     *
     * @param keyBlockSize
     * @param data
     * @return
     */
    public static byte[] ISO9797_1Padding_Method1(int keyBlockSize, byte[] data) {
        if (data.length % keyBlockSize != 0) {
            byte[] padding = new byte[keyBlockSize - data.length % keyBlockSize];
            Arrays.fill(padding, (byte) 0x00);
            return Bytes.concat(data, padding);
        } else {
            return data;
        }
    }

    /**
     * ISO9797-1 Padding Method 1
     *
     * @param keyBlockSize
     * @param data
     * @return
     */
    public static byte[] ISO9797_1Padding_Method2(int keyBlockSize, byte[] data) {
        byte[] padding;
        if (data.length % keyBlockSize != 0) {
            padding = new byte[keyBlockSize - data.length % keyBlockSize];
        } else {
            padding = new byte[keyBlockSize];
        }
        Arrays.fill(padding, (byte) 0x00);
        padding[0] = (byte) 0x80;
        return Bytes.concat(data, padding);
    }

    /**
     * ISO9797-1 Padding Method 1
     *
     * @param keyBlockSize
     * @param data
     * @return
     */
    public static byte[] ISO9797_1Padding_Method3(int keyBlockSize, byte[] data) {
        int dataBitSize = data.length * 8;
        byte[] paddingStart = Bytes
                .fromHexString(FormatUtil.addHead('0', keyBlockSize * 2, Integer.toHexString(dataBitSize)));
        if (data.length % keyBlockSize != 0) {
            byte[] paddingEnd = new byte[keyBlockSize - data.length % keyBlockSize];
            Arrays.fill(paddingEnd, (byte) 0x00);
            return Bytes.concat(paddingStart, data, paddingEnd);
        } else {
            return Bytes.concat(paddingStart, data);
        }
    }

    /**
     * ISO9797-1 MAC Algorithm1
     *
     * @param key
     * @param data
     * @param padding
     * @return
     */
    public static byte[] ISO9797_1_MACAlgorithm1(byte[] key, byte[] data, MacAlgorithmPadding padding) {
        if (padding == MacAlgorithmPadding.Method1) {
            data = ISO9797_1Padding_Method1(8, data);
        } else if (padding == MacAlgorithmPadding.Method2) {
            data = ISO9797_1Padding_Method2(8, data);
        } else if (padding == MacAlgorithmPadding.Method3) {
            data = ISO9797_1Padding_Method3(8, data);
        }
        byte[] iv = new byte[8];
        byte[] h = null;
        byte[] d = null;
        for (int round = 0; round < data.length / 8; round++) {
            d = Bytes.subBytes(data, round * 8, 8);
            if (round > 0) {
                d = Bytes.xor(d, h);
                // PrintfUtil.d("D"+(round+1)+"+"+"H"+(round), Bytes.toHexString(d));
            }
            h = encrypt(SymmetryAlgorithm.DES, SymmetryModel.CBC, SymmetryPadding.NoPadding, key, iv, d);
            // PrintfUtil.d("H"+(round+1), Bytes.toHexString(h));
        }
        return h;
    }

    /**
     * ISO9797-1 MAC Algorithm3
     *
     * @param key
     * @param data
     * @param padding
     * @return
     */
    public static byte[] ISO9797_1_MACAlgorithm3(byte[] key, byte[] data, MacAlgorithmPadding padding) {
        byte[] out = new byte[8];
        if (key.length != 16) {
            throw new IllegalArgumentException("key length must be 16 bytes");
        }
        if (padding == MacAlgorithmPadding.Method1) {
            data = ISO9797_1Padding_Method1(8, data);
        } else if (padding == MacAlgorithmPadding.Method2) {
            data = ISO9797_1Padding_Method2(8, data);
        } else if (padding == MacAlgorithmPadding.Method3) {
            data = ISO9797_1Padding_Method3(8, data);
        }
        BlockCipher cipher = new DESEngine();
        org.bouncycastle.crypto.Mac mac = new ISO9797Alg3Mac(cipher, 64);
        KeyParameter keyParameter = new KeyParameter(key);
        mac.init(keyParameter);
        mac.update(data, 0, data.length);
        mac.doFinal(out, 0);
        return out;
    }

    /**
     * ISO16609_1 MAC Algorithm1
     *
     * @param key
     * @param data
     * @param padding
     * @return
     */
    public static byte[] ISO16609_1_MACAlgorithm1(byte[] key, byte[] data, MacAlgorithmPadding padding) {
        if (padding == MacAlgorithmPadding.Method1) {
            data = ISO9797_1Padding_Method1(8, data);
        } else if (padding == MacAlgorithmPadding.Method2) {
            data = ISO9797_1Padding_Method2(8, data);
        } else if (padding == MacAlgorithmPadding.Method3) {
            data = ISO9797_1Padding_Method3(8, data);
        }
        byte[] iv = new byte[8];
        byte[] h = null;
        byte[] d = null;
        for (int round = 0; round < data.length / 8; round++) {
            d = Bytes.subBytes(data, round * 8, 8);
            if (round > 0) {
                d = Bytes.xor(d, h);
                // PrintfUtil.d("D"+(round+1)+"+"+"H"+(round), Bytes.toHexString(d));
            }
            h = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.SymmetryModel.CBC,
                    AlgUtil.SymmetryPadding.NoPadding, key, iv, d);
            // PrintfUtil.d("H"+(round+1), Bytes.toHexString(h));
        }
        return h;
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
     * HMAC
     *
     * @param digest
     * @param key
     * @param data
     */
    public static byte[] hmac(Digest digest, byte[] key, byte[] data) {
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        return result;
    }

    /**
     * @param key
     * @return
     */
    public static byte[] desLegacyKCV(byte[] key) {
        byte[] zero = new byte[8];
        Arrays.fill(zero, (byte) 0x00);
        return encrypt(SymmetryAlgorithm.DES, SymmetryModel.CBC, SymmetryPadding.NoPadding, key, zero, zero);
    }

    /**
     * @param key
     * @return
     */
    public static byte[] tdesLegacyKCV(byte[] key) {
        byte[] zero = new byte[8];
        Arrays.fill(zero, (byte) 0x00);
        return encrypt(SymmetryAlgorithm.TDES, SymmetryModel.CBC, SymmetryPadding.NoPadding, key, zero, zero);
    }

    /**
     * @param key
     * @return
     */
    public static byte[] aesLegacyKCV(byte[] key) {
        byte[] zero = new byte[16];
        Arrays.fill(zero, (byte) 0x00);
        return encrypt(SymmetryAlgorithm.AES, SymmetryModel.CBC, SymmetryPadding.NoPadding, key, zero, zero);
    }

    /**
     * 计算KCV
     *
     * @param key
     * @return
     */
    public static byte[] tdesCMACKCV(byte[] key) {
        byte[] zero = new byte[8];
        Arrays.fill(zero, (byte) 0x00);
        return tdesCMAC(key, zero);
    }

    /**
     * 计算KCV
     *
     * @param key
     * @return
     */
    public static byte[] aesCMACKCV(byte[] key) {
        byte[] zero = new byte[16];
        Arrays.fill(zero, (byte) 0x00);
        return aesCMAC(key, zero);
    }

    /**
     * Ingenic HMAC Key Check Value
     *
     * @param key
     * @return
     */
    public static byte[] ingenicHMACKCV(byte[] key) {
        if (key.length == 16) {
            return hmac(new SHA256Digest(), key, "".getBytes());
        } else if (key.length == 24) {
            return hmac(new SHA384Digest(), key, "".getBytes());
        } else if (key.length == 32) {
            return hmac(new SHA512Digest(), key, "".getBytes());
        } else {
            throw new IllegalArgumentException("key length error");
        }
    }

    /**
     * Ingenic Data Check Value Secret Client Data are non-PCI data. They are used
     * by customers to store proprietary data which are not keys. However, these
     * client data need to be kept secret. For instance, these data can be serial
     * numbers, key derivation constant etc...
     * <p>
     * Cleartext Client Data are non-PCI data. They are used by customers to store
     * proprietary data which are not keys and not sensitive. For instance, these
     * data can be a text or a random value that need to be stored. Check Values for
     * Cleartext Client Data use the technique where the check value is calculated
     * by Hashing the secret client data using the SHA-256 algorithm. The check
     * value is the leftmost 6 hexadecimal digits (3 bytes).
     *
     * @param data
     * @param secret
     * @return
     */
    public static byte[] ingenicDCV(byte[] data, boolean secret) {
        if (!secret) {
            return hash(HashAlgorithm.SHA256, data);
        } else {
            if (data.length == 8) {
                return desLegacyKCV(data);
            } else if (data.length >= 16) {
                return hash(HashAlgorithm.SHA256, data);
            } else {
                throw new IllegalArgumentException("data length error");
            }
        }
    }

    /**
     * TDES DUKPT IK 衍生
     *
     * @param bdk
     * @param ksn
     * @return
     */
    public static byte[] tdesIK(byte[] bdk, byte[] ksn) {
        // TDES DUKPT 没有24字节密钥
        if (bdk.length != 16) {
            throw new IllegalArgumentException("bdk length error");
        }
        if (ksn.length != 10) {
            throw new IllegalArgumentException("ksn length error");
        }
        byte[] ik;
        byte[] makeEBdk = new byte[]{(byte) 0xC0, (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00,
                (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00};
        byte[] ksnTmp = Bytes.subBytes(ksn, 0, 8);
        // 根据算法需要把原来的80个bit的KSN后21bit清零
        ksnTmp[7] &= 0xE0;
        ik = encrypt(SymmetryAlgorithm.TDES, SymmetryModel.ECB, SymmetryPadding.NoPadding, bdk, null, ksnTmp);
        // bdk与makeEBdk异或
        byte[] xorTmp = Bytes.xor(bdk, makeEBdk);
        xorTmp = encrypt(SymmetryAlgorithm.TDES, SymmetryModel.ECB, SymmetryPadding.NoPadding, xorTmp, null, ksnTmp);
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
            byte[] result = encrypt(SymmetryAlgorithm.AES, SymmetryModel.ECB, SymmetryPadding.NoPadding, bdk, null,
                    derivData);
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

    /**
     * 非对称填充
     */
    public enum AsymmetricPadding {

        NoPadding("NoPadding"),
        PKCS1Padding("PKCS1Padding"),
        OAEPWithSHA256AndMGF1Padding("OAEPWithSHA256AndMGF1Padding"),
        OAEPWithSHA512AndMGF1Padding("OAEPWithSHA512AndMGF1Padding");

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
     * 生成RSA公私钥对
     *
     * @param modulus
     * @param exponent
     * @return
     */
    public static KeyPair generateRSAKeyPair(int modulus, int exponent) {
        if (!(modulus == 1024 || modulus == 2048 || modulus == 3072 || modulus == 4096)) {
            throw new IllegalArgumentException("RSA modulus error");
        }
        KeyPair keyPair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            BigInteger publicExponent = new BigInteger(Integer.toHexString(exponent), 16);
            RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(modulus, publicExponent);
            generator.initialize(parameterSpec, new SecureRandom());
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * RSA公钥计算
     *
     * @param padding
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] RSAPublicKeyCalc(AsymmetricPadding padding, RSAPublicKey publicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA" + "/" + "NONE" + "/" + padding.getName());
            cipher.init(Cipher.PUBLIC_KEY, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA私钥计算
     *
     * @param padding
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] RSAPrivateKeyCalc(AsymmetricPadding padding, RSAPrivateCrtKey privateKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA" + "/" + "NONE" + "/" + padding.getName());
            cipher.init(Cipher.PRIVATE_KEY, privateKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA签名方式
     */
    public enum RSASignType {
        NONEwithRSA("NONEwithRSA"),
        SHA256withRSA("SHA256withRSA"),
        SHA384withRSA("SHA384withRSA"),
        SHA512withRSA("SHA512withRSA"),
        SHA256withRSA_PSS("SHA256withRSA/PSS"),
        SHA384withRSA_PSS("SHA384withRSA/PSS"),
        SHA512withRSA_PSS("SHA512withRSA/PSS");

        private String name;

        private RSASignType(final String name) {
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
     * RSA签名
     *
     * @param type
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] RSASign(RSASignType type, RSAPrivateCrtKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance(type.getName());
            if (type.getName().endsWith("PSS")) {
                if (type.equals(RSASignType.SHA256withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA256.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA256, 32, 1));
                } else if (type.equals(RSASignType.SHA384withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA384.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA384, 48, 1));
                } else if (type.equals(RSASignType.SHA512withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA512.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA512, 64, 1));
                }
            }
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signed = signature.sign();
            return signed;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException
                | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA签名验证
     *
     * @param type
     * @param publicKey
     * @param data
     * @param signed
     * @return
     */
    public static boolean RSASignVerify(RSASignType type, RSAPublicKey publicKey, byte[] data, byte[] signed) {
        try {
            Signature signature = Signature.getInstance(type.getName());
            if (type.getName().endsWith("PSS")) {
                if (type.equals(RSASignType.SHA256withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA256.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA256, 32, 1));
                } else if (type.equals(RSASignType.SHA384withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA384.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA384, 48, 1));
                } else if (type.equals(RSASignType.SHA512withRSA_PSS.getName())) {
                    signature.setParameter(new PSSParameterSpec(MGF1ParameterSpec.SHA512.getDigestAlgorithm(), "MGF1",
                            MGF1ParameterSpec.SHA512, 64, 1));
                }
            }
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signed);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException
                | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * ECC曲线
     */
    public enum ECCCurve {

        secp224r1("secp224r1", 2),
        secp256r1("secp256r1", 3),
        secp384r1("secp384r1", 4),
        secp521r1("secp521r1", 5),
        brainpoolp256r1("brainpoolp256r1", 6),
        brainpoolp384r1("brainpoolp384r1", 7),
        brainpoolp512r1("brainpoolp512r1", 8),
        P_224("P-224", 2),
        P_256("P-256", 3),
        P_384("P-384", 4),
        P_521("P-521", 5);

        private String name;
        private int value;

        private ECCCurve(final String name, int value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public void setName(final String name) {
            this.name = name;
        }

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }

    /**
     * 生成ECC公私钥对
     *
     * @param eccCurve
     * @return
     */
    public static KeyPair generateECCKeyPair(ECCCurve eccCurve) {
        KeyPair keyPair = null;
        try {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(eccCurve.getName());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDH");
            generator.initialize(parameterSpec, new SecureRandom());
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * ECC签名方式
     */
    public enum ECCSignType {
        NONEwithECDSA("NONEwithECDSA"),
        SHA256withECDSA("SHA256withECDSA"),
        SHA384withECDSA("SHA384withECDSA"),
        SHA512withECDSA("SHA512withECDSA");

        private String name;

        private ECCSignType(final String name) {
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
     * ECC签名
     *
     * @param type
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] ECCSign(ECCSignType type, ECPrivateKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance(type.getName());
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signed = signature.sign();
            return signed;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解析ECC签名数据得到R/S
     *
     * @param signed
     * @return
     */
    public static ECCSigned parseECCSigned(byte[] signed) {
        return new ECCSigned(signed);
    }

    /**
     * 签名的主体分为R和S两部分。R(或S)的长度等于ECC私钥长度。R(或S)前的T为0x02，签名T为0x30。总体格式如下：
     * 30 + LEN1 + 02 + LEN2 + 00 (optional) + r + 02 + LEN3 + 00(optional) + s
     * 当R或S的第1字节大于0x80时，需要在R或S前加1字节0x00
     * LEN2为，0x00(optional) + R 的字节长度
     * LEN3为，0x00(optional) + S 的字节长度
     * LEN1为，LEN2+LEN3+4字节长度
     *
     * @author yun
     */
    public static class ECCSigned {
        private byte[] R;
        private byte[] S;

        public ECCSigned(byte[] signed) {
            parse(signed);
        }

        public ECCSigned(byte[] R, byte[] S) {
            this.R = R;
            this.S = S;
        }

        public byte[] getR() {
            return R;
        }

        public byte[] getS() {
            return S;
        }

        private void parse(byte[] signed) {
            List<TLVUtil.TLV> tlv = TLVUtil.parseDER(signed);
            this.R = tlv.get(0).getChildren().get(0).getValue();
            if (R[0] == 0x00) {
                this.R = Bytes.subBytes(R, 1);
            }
            this.S = tlv.get(0).getChildren().get(1).getValue();
            if (S[0] == 0x00) {
                this.S = Bytes.subBytes(S, 1);
            }
        }

        public byte[] getSigned() {
            byte[] tag = new byte[]{0x30};
            byte[] tagR = new byte[]{0x02};
            if ((this.R[0] & 0xFF) >= 0x80) {
                this.R = Bytes.concat(new byte[]{0x00}, this.R);
            }
            byte[] lenR = Bytes.getDERLen(this.R.length);
            byte[] tagS = new byte[]{0x02};
            if ((this.S[0] & 0xFF) >= 0x80) {
                this.S = Bytes.concat(new byte[]{0x00}, this.S);
            }
            byte[] lenS = Bytes.getDERLen(this.S.length);
            byte[] signed = Bytes.concat(tagR, lenR, R, tagS, lenS, S);
            return Bytes.concat(tag, Bytes.getDERLen(signed.length), signed);
        }
    }

    /**
     * ECC签名验证
     *
     * @param type
     * @param publicKey
     * @param data
     * @param signed
     * @return
     */
    public static boolean ECCSignVerify(ECCSignType type, ECPublicKey publicKey, byte[] data, byte[] signed) {
        try {
            Signature signature = Signature.getInstance(type.getName());
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signed);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 获得共享密钥
     *
     * @param myPrivateKey
     * @param otherPublicKey
     * @return
     */
    public static byte[] getShareKey(ECPrivateKey myPrivateKey, ECPublicKey otherPublicKey) {
        byte[] shareKey = null;
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(myPrivateKey);
            agreement.doPhase(otherPublicKey, true);
            shareKey = agreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return shareKey;
    }

    /**
     * HKDF
     *
     * @param digest
     * @param salt
     * @param info
     * @param ikm
     * @param keyLen
     * @return
     */
    public static byte[] hkdf(Digest digest, byte[] salt, byte[] info, byte[] ikm, int keyLen) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        HKDFParameters params = new HKDFParameters(ikm, salt, info);
        hkdf.init(params);
        byte[] okm = new byte[keyLen];
        hkdf.generateBytes(okm, 0, keyLen);
        return okm;
    }


    /**
     * Ingenic ECDH 派生算法
     *
     * @param shareKey
     * @param KDF1PublicKeyHex
     * @param krdRandom
     * @param kdhRandom
     * @param label(KeyBlockProtect\DataEncryption\MesAuthentCode)
     * @param algorithm
     * @param keyLen
     * @param KDF1Digest
     * @param KDF2Digest
     * @return
     */
    public static byte[] ingenicECDHDerivedKey(byte[] shareKey, String KDF1PublicKeyHex, byte[] krdRandom, byte[] kdhRandom,
                                               String label, byte algorithm, int keyLen, Digest KDF1Digest, Digest KDF2Digest) {
        ECPublicKey ecPublicKey = CertUtil.hex2ECPublicKey(AlgUtil.ECCCurve.P_521, KDF1PublicKeyHex);
        byte[] Pub_X = Bytes.fromHexString('0' + ecPublicKey.getW().getAffineX().toString(16));
        byte[] extractionResult = AlgUtil.hmac(KDF1Digest, Pub_X, shareKey);
        byte[] keyMaterial = PRF(extractionResult,
                1, Bytes.ENDIAN.LITTLE_ENDIAN,
                "KDK".getBytes(),
                Bytes.concat(Pub_X, krdRandom, kdhRandom),
                256, 2, Bytes.ENDIAN.BIG_ENDIAN,
                KDF1Digest);
        byte[] derivedKeyContext = null;
        if (algorithm == KeyAlgorithm.TDEA && keyLen == 24) {
            derivedKeyContext = new byte[]{0x00, 0x01, 0x00, (byte) 0xC0};
        } else if (algorithm == KeyAlgorithm.AES && keyLen == 16) {
            derivedKeyContext = new byte[]{0x00, 0x02, 0x00, (byte) 0x80};
        } else if (algorithm == KeyAlgorithm.AES && keyLen == 24) {
            derivedKeyContext = new byte[]{0x00, 0x03, 0x00, (byte) 0xC0};
        } else if (algorithm == KeyAlgorithm.AES && keyLen == 32) {
            derivedKeyContext = new byte[]{0x00, 0x04, 0x01, 0x00};
        } else {
            throw new IllegalArgumentException("IngenicECDHDerivedKey Algorithm unknown");
        }
        byte[] derivedKey = PRF(keyMaterial,
                4, Bytes.ENDIAN.LITTLE_ENDIAN,
                Strings.encode(label),
                derivedKeyContext,
                keyLen * 8, 4, Bytes.ENDIAN.LITTLE_ENDIAN,
                KDF2Digest);
        return derivedKey;
    }

    /**
     * Landi ECDH 派生算法
     *
     * @param shareKey
     * @param KDF1PublicKeyHex
     * @param krdRandom
     * @param kdhRandom
     * @param label(KBPK/KEAK/MacKey/DataKey)
     * @param keyLen
     * @param KDF1Digest
     * @param KDF2Digest
     * @return
     */
    public static byte[] landiECDHDerivedKey(byte[] shareKey, String KDF1PublicKeyHex, byte[] krdRandom, byte[] kdhRandom,
                                             String label, int keyLen, Digest KDF1Digest, Digest KDF2Digest) {
        ECPublicKey ecPublicKey = CertUtil.hex2ECPublicKey(AlgUtil.ECCCurve.P_521, KDF1PublicKeyHex);
        byte[] Pub_X = Bytes.fromHexString('0' + ecPublicKey.getW().getAffineX().toString(16));
        byte[] extractionResult = AlgUtil.hmac(KDF1Digest, Bytes.concat(Pub_X, krdRandom, kdhRandom), shareKey);
        byte[] keyMaterial = PRF(extractionResult,
                4, Bytes.ENDIAN.LITTLE_ENDIAN,
                "KDK".getBytes(),
                Bytes.concat(Pub_X, krdRandom, kdhRandom),
                256, 4, Bytes.ENDIAN.LITTLE_ENDIAN,
                KDF1Digest);
        byte[] derivedKey = PRF(keyMaterial,
                4, Bytes.ENDIAN.LITTLE_ENDIAN,
                Strings.encode(label),
                Strings.encode("KRD and KDH"),
                keyLen * 8, 4, Bytes.ENDIAN.LITTLE_ENDIAN,
                KDF2Digest);
        return derivedKey;
    }


    /**
     * PRF运算
     *
     * @param inputKey
     * @param counterLength
     * @param counterEndian
     * @param label
     * @param context
     * @param LBits
     * @param LLength
     * @param LEndian
     * @return
     */
    private static byte[] PRF(byte[] inputKey, int counterLength, Bytes.ENDIAN counterEndian, byte[] label, byte[] context,
                              int LBits, int LLength, Bytes.ENDIAN LEndian, Digest digest) {
        int counter = 1;
        byte[] separator = new byte[]{0x00};
        int saltSize = 0;
        if (digest instanceof SHA256Digest) {
            saltSize = 256;
        } else if (digest instanceof SHA384Digest) {
            saltSize = 384;
        } else if (digest instanceof SHA512Digest) {
            saltSize = 512;
        } else {
            throw new IllegalArgumentException("Unknown digest");
        }
        int round = LBits / saltSize;
        byte[] Context;
        byte[] nKey;
        String nKeyBits;
        byte[] outputKey = null;
        if (round == 0) {
            Context = Bytes.concat(Bytes.fromInt(counter, counterLength, counterEndian), label, separator,
                    context,
                    Bytes.fromInt(LBits, LLength, LEndian));
            nKey = AlgUtil.hmac(digest, inputKey, Context);
            // 截取有效Bits
            nKeyBits = Bytes.toBitString(nKey).substring(0, LBits);
            // 左补0
            nKeyBits = FormatUtil.addHead('0', 8 - LBits % 8, nKeyBits);
            nKey = Bytes.bitString2Byte(nKeyBits);
            outputKey = nKey;
        } else {
            for (int i = 0; i < round; i++) {
                Context = Bytes.concat(Bytes.fromInt(counter, counterLength, counterEndian), label, separator,
                        context,
                        Bytes.fromInt(LBits, LLength, LEndian));
                nKey = AlgUtil.hmac(digest, inputKey, Context);
                if (Bytes.isNullOrEmpty(outputKey)) {
                    outputKey = nKey;
                } else {
                    outputKey = Bytes.concat(outputKey, nKey);
                }
                counter++;
            }
            if (LBits % saltSize != 0) {
                Context = Bytes.concat(Bytes.fromInt(counter, counterLength, counterEndian), label, separator,
                        context,
                        Bytes.fromInt(LBits, LLength, LEndian));
                nKey = AlgUtil.hmac(digest, inputKey, Context);
                // 截取有效Bits
                nKeyBits = Bytes.toBitString(nKey).substring(0, LBits);
                // 左补0
                nKeyBits = FormatUtil.addHead('0', 8 - LBits % 8, nKeyBits);
                nKey = Bytes.bitString2Byte(nKeyBits);
                outputKey = Bytes.concat(outputKey, nKey);
            }
        }
        return outputKey;
    }

}