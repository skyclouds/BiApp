package com.biapp.util;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.engines.DESEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.macs.ISO9797Alg3Mac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
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

    // 增加BouncyCastle
    private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        Security.insertProviderAt(BOUNCY_CASTLE_PROVIDER, 1);
    }

    /**
     * 对称算法
     */
    public enum SymmetryAlgorithm {

        DES("DES"), TDES("DESede"), AES("AES"), SM4("SM4");

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

        ECB("ECB"), CBC("CBC"), GCM("GCM"), CTR("CTR");

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

        NoPadding("NoPadding"), ZeroBytePadding("ZeroBytePadding"), PKCS5Padding("PKCS5Padding"),
        PKCS7Padding("PKCS7Padding"), ISO9797_1Padding("ISO9797-1Padding"), ISO7816_4Padding("ISO7816-4Padding"),
        ISO10126Padding("ISO10126Padding"), ISO10126_2Padding("ISO10126-2Padding"), X923Padding("X923Padding"),
        X9_23Padding("X9.23Padding");

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

        MD2("MD2"), MD4("MD4"), MD5("MD5"), SHA1("SHA-1"), SHA224("SHA-224"), SHA256("SHA-256"), SHA384("SHA-384"),
        SHA512("SHA-512"), SHA3_224("SHA3-224"), SHA3_256("SHA3-256"), SHA3_384("SHA3-384"), SHA3_512("SHA3-512"),
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
     * MAC算法
     */
    public enum MACAlgorithm {

        MD5withRSA("MD5withRSA"), SHA1withRSA("SHA1withRSA"), SHA224withRSA("SHA224withRSA"),
        SHA256withRSA("SHA256withRSA"), SHA384withRSA("SHA384withRSA"), SHA512withRSA("SHA512withRSA"),
        SHA3_224withRSA("SHA3-224withRSA"), SHA3_256withRSA("SHA3-256withRSA"), SHA3_384withRSA("SHA3-384withRSA"),
        SHA3_512withRSA("SHA3-512withRSA"), SHA256withSM2("SHA256withSM2"), SM3withSM2("SM3withSM2");

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
        byte[] paddingStart = Bytes.fromHexString(FormatUtil.addHead('0', keyBlockSize * 2, Integer.toHexString(dataBitSize)));
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
                //PrintfUtil.d("D"+(round+1)+"+"+"H"+(round), Bytes.toHexString(d));
            }
            h = encrypt(SymmetryAlgorithm.DES, SymmetryModel.CBC, SymmetryPadding.NoPadding, key, iv, d);
            //PrintfUtil.d("H"+(round+1), Bytes.toHexString(h));
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
        org.spongycastle.crypto.Mac mac = new ISO9797Alg3Mac(cipher, 64);
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
                //PrintfUtil.d("D"+(round+1)+"+"+"H"+(round), Bytes.toHexString(d));
            }
            h = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.NoPadding, key, iv, d);
            //PrintfUtil.d("H"+(round+1), Bytes.toHexString(h));
        }
        return h;
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
     * TDES MCAC
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] tdesCMAC(byte[] key, byte[] data) {
        byte[] cmac = new byte[8];
        BlockCipher cipher = new DESedeEngine();
        org.spongycastle.crypto.Mac mac = new CMac(cipher, 64);
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
        org.spongycastle.crypto.Mac mac = new CMac(cipher, 128);
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
        xorTmp = encrypt(SymmetryAlgorithm.TDES, SymmetryModel.ECB, SymmetryPadding.NoPadding, xorTmp, null,
                ksnTmp);
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
            byte[] result = encrypt(SymmetryAlgorithm.AES, SymmetryModel.ECB, SymmetryPadding.NoPadding, bdk,
                    null, derivData);
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
     * 非对称模式
     */
    public enum AsymmetricModel {

        NONE("NONE");

        private String name;

        private AsymmetricModel(final String name) {
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

        NoPadding("NoPadding");

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
            BigInteger publicExponent = new BigInteger(exponent + "", 10);
            RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(modulus, publicExponent);
            generator.initialize(parameterSpec);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * 加密
     *
     * @param model
     * @param padding
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] encrypt(AsymmetricModel model, AsymmetricPadding padding, RSAPublicKey publicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA" + "/" + model.getName() + "/" + padding.getName());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param model
     * @param padding
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] decrypt(AsymmetricModel model, AsymmetricPadding padding, RSAPrivateCrtKey privateKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA" + "/" + model.getName() + "/" + padding.getName());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ECC曲线
     */
    public enum ECCCurve {

        secp224r1("secp224r1"), secp256r1("secp256r1"), secp384r1("secp384r1"), secp521r1("secp521r1"),
        brainpoolp256r1("brainpoolp256r1"), brainpoolp384r1("brainpoolp384r1"), brainpoolp512r1("brainpoolp512r1");

        private String name;

        private ECCCurve(final String name) {
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
            generator.initialize(parameterSpec);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

}