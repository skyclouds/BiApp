package com.biapp.util;

import com.biapp.util.AlgUtil;
import com.biapp.util.FormatUtil;
import com.biapp.util.TLVUtil;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import aura.data.Bytes;
import aura.data.Strings;

/**
 * @author yun
 */
public class CertUtil {

    // 增加BouncyCastle
    private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        Security.insertProviderAt(BOUNCY_CASTLE_PROVIDER, 1);
    }

    /**
     * 获得证书X509项信息包括
     * 1 证书版本信息
     * 2 证书序列号
     * 3 签名算法描述
     * 4 证书颁发者信息
     * 5 有效期信息
     * 6 主题信息
     * 7 公钥信息
     * 8 扩展信息
     * 9 签名算法信息
     * 10 签名信息
     * X.509证书结构为：X.509证书结构长度+证书长度+证书信息(1 证书版本信息 2 证书序列号 3 签名算法描述 4 证书颁发者信息 5 有效期信息 6
     * 主题信息 7 公钥信息 8 扩展信息)+签名算法信息+签名信息
     *
     * @param certData
     * @return
     */
    public static List<TLVUtil.TLV> getCertX509Items(byte[] certData) {
        List<TLVUtil.TLV> x509Items = new ArrayList<>();
        List<TLVUtil.TLV> tlvs = TLVUtil.parseDER(certData);
        if (tlvs != null && !tlvs.isEmpty()) {
            if (tlvs.get(0).getChildren() != null && !tlvs.get(0).getChildren().isEmpty()) {
                TLVUtil.TLV certInfos = tlvs.get(0).getChildren().get(0);
                if (certInfos.getChildren() != null && !certInfos.getChildren().isEmpty() && certInfos.getChildren().size() == 8) {
                    x509Items = new ArrayList<>();
                    x509Items.add(certInfos.getChildren().get(0));
                    x509Items.add(certInfos.getChildren().get(1));
                    x509Items.add(certInfos.getChildren().get(2));
                    x509Items.add(certInfos.getChildren().get(3));
                    x509Items.add(certInfos.getChildren().get(4));
                    x509Items.add(certInfos.getChildren().get(5));
                    x509Items.add(certInfos.getChildren().get(6));
                    x509Items.add(certInfos.getChildren().get(7));
                    if (tlvs.size() == 3) {
                        x509Items.add(tlvs.get(0).getChildren().get(1));
                        x509Items.add(tlvs.get(0).getChildren().get(2));
                    }
                }
            }
        }
        return x509Items;
    }

    /**
     * PEM格式证书转X509Certificate
     *
     * @param pem
     * @return
     */
    public static X509Certificate pem2Cert(String pem) {
        pem = pem.replaceAll("\r|\n", "");
        if (pem.startsWith("-----BEGIN CERTIFICATE-----") && pem.endsWith("-----END CERTIFICATE-----")) {
            pem = pem.replace("-----BEGIN CERTIFICATE-----", "");
            pem = pem.replace("-----END CERTIFICATE-----", "");
            pem = FormatUtil.removeAllSpace(pem);
            return getCertificate(Bytes.fromBase64String(pem));
        } else {
            throw new IllegalArgumentException("parse PEM foramt error");
        }
    }

    /**
     * 获得证书
     *
     * @param certData
     * @return
     */
    public static X509Certificate getCertificate(byte[] certData) {
        X509Certificate cert = null;
        try {
            InputStream inputStream = new ByteArrayInputStream(certData);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    /**
     * 获得公钥
     *
     * @param certData
     * @return
     */
    public static RSAPublicKey getPublicKey(byte[] certData) {
        RSAPublicKey publicKey = null;
        try {
            InputStream inputStream = new ByteArrayInputStream(certData);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            publicKey = (RSAPublicKey) cert.getPublicKey();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * PEM转RSAPublicKey
     *
     * @param pem
     * @return
     * @throws IllegalArgumentException
     */
    public static RSAPublicKey pem2RSAPublicKey(String pem) throws IllegalArgumentException {
        RSAPublicKey publicKey = null;
        try {
            pem = pem.replaceAll("\r|\n", "");
            if (pem.startsWith("-----BEGIN RSA PUBLIC KEY-----") && pem.endsWith("-----END RSA PUBLIC KEY-----")) {
                // PKCS1格式
                pem = pem.replace("-----BEGIN RSA PUBLIC KEY-----", "");
                pem = pem.replace("-----END RSA PUBLIC KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs1 = Bytes.fromBase64String(pem);
                List<TLVUtil.TLV> tls = TLVUtil.parseDER(pkcs1);
                BigInteger modulus = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(0).getValue()), 16);
                BigInteger exponent = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(1).getValue()), 16);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            } else if (pem.startsWith("-----BEGIN PUBLIC KEY-----") && pem.endsWith("-----END PUBLIC KEY-----")) {
                // PKCS8格式
                pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
                pem = pem.replace("-----END PUBLIC KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs8 = Bytes.fromBase64String(pem);
                List<TLVUtil.TLV> tls = TLVUtil.parseDER(pkcs8);
                BigInteger modulus = new BigInteger(
                        Bytes.toHexString(
                                tls.get(0).getChildren().get(1).getChildren().get(0).getChildren().get(0).getValue()),
                        16);
                BigInteger exponent = new BigInteger(
                        Bytes.toHexString(
                                tls.get(0).getChildren().get(1).getChildren().get(0).getChildren().get(1).getValue()),
                        16);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            } else {
                throw new IllegalArgumentException("parse PEM foramt error");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * PEM转RSAPrivateCrtKey
     *
     * @param pem
     * @return
     * @throws IllegalArgumentException
     */
    public static RSAPrivateCrtKey pem2RSAPrivateKey(String pem) throws IllegalArgumentException {
        RSAPrivateCrtKey privateKey = null;
        try {
            pem = pem.replaceAll("\r|\n", "");
            if (pem.startsWith("-----BEGIN RSA PRIVATE KEY-----") && pem.endsWith("-----END RSA PRIVATE KEY-----")) {
                // PKCS1格式
                pem = pem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
                pem = pem.replace("-----END RSA PRIVATE KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs1 = Bytes.fromBase64String(pem);
                List<TLVUtil.TLV> tls = TLVUtil.parseDER(pkcs1);
                BigInteger modulus = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(1).getValue()), 16);
                BigInteger publicExponent = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getValue()), 16);
                BigInteger privateExponent = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(3).getValue()), 16);
                BigInteger primeP = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(4).getValue()), 16);
                BigInteger primeQ = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(5).getValue()), 16);
                BigInteger primeExponentP = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(6).getValue()), 16);
                BigInteger primeExponentQ = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(7).getValue()), 16);
                BigInteger coefficient = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(8).getValue()), 16);
                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent,
                        primeP, primeQ, primeExponentP, primeExponentQ, coefficient);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            } else if (pem.startsWith("-----BEGIN PRIVATE KEY-----") && pem.endsWith("-----END PRIVATE KEY-----")) {
                // PKCS8格式
                pem = pem.replace("-----BEGIN PRIVATE KEY-----", "");
                pem = pem.replace("-----END PRIVATE KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs8 = Bytes.fromBase64String(pem);
                List<TLVUtil.TLV> tls = TLVUtil.parseDER(pkcs8);
                BigInteger modulus = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(1).getValue()), 16);
                BigInteger publicExponent = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(2).getValue()), 16);
                BigInteger privateExponent = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(3).getValue()), 16);
                BigInteger primeP = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(4).getValue()), 16);
                BigInteger primeQ = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(5).getValue()), 16);
                BigInteger primeExponentP = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(6).getValue()), 16);
                BigInteger primeExponentQ = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(7).getValue()), 16);
                BigInteger coefficient = new BigInteger(Bytes.toHexString(tls.get(0).getChildren().get(2).getChildren().get(0).getChildren().get(8).getValue()), 16);
                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent,
                        primeP, primeQ, primeExponentP, primeExponentQ, coefficient);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            } else {
                throw new IllegalArgumentException("parse PEM foramt error");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * RSAPublicKey类对象解析成6进制数据
     *
     * @param publicKey
     * @return
     */
    public static byte[] RSAPublicKey2Hex(RSAPublicKey publicKey) {
        byte[] hex = Bytes.concat(Bytes.fromHexString(publicKey.getModulus().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(FormatUtil.addHead('0', publicKey.getModulus().bitLength() / 4, publicKey.getPublicExponent().toString(16))));
        return Bytes.concat(Bytes.fromInt(publicKey.getModulus().bitLength(), 4, Bytes.ENDIAN.LITTLE_ENDIAN), hex);
    }

    /**
     * 将公钥16进制数据解析成RSAPublicKey类对象
     *
     * @param hex
     * @return
     */
    public static RSAPublicKey hex2RSAPublicKey(String hex) {
        RSAPublicKey publicKey = null;
        try {
            byte[] hexData = Bytes.fromHexString(hex);
            byte[] tmp;
            int index = 0;
            // 公钥bits
            int bits;
            tmp = Bytes.subBytes(hexData, 0, 4);
            index += 4;
            bits = (tmp[0] & 0xFF) * 256 * 256 + (tmp[1] & 0xFF) * 256 + (tmp[2] & 0xFF);
            // 公钥modulus
            tmp = Bytes.subBytes(hexData, index, bits / 8);
            index += bits / 8;
            BigInteger modulus = new BigInteger(Bytes.toHexString(tmp), 16);
            // 公钥exponent
            tmp = Bytes.subBytes(hexData, index, bits / 8);
            index += bits / 8;
            BigInteger exponent = new BigInteger(Bytes.toHexString(tmp), 16);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * RSAPrivateCrtKey类对象解析成6进制数据
     *
     * @param privateKey
     * @return
     */
    public static byte[] RSAPrivateCrtKey2Hex(RSAPrivateCrtKey privateKey) {
        byte[] hex = Bytes.concat(Bytes.fromHexString(privateKey.getModulus().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(FormatUtil.addHead('0', privateKey.getModulus().bitLength() / 4, privateKey.getPublicExponent().toString(16))),
                Bytes.fromHexString(privateKey.getPrivateExponent().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeP().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeQ().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeExponentP().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeExponentQ().toString(16), Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getCrtCoefficient().toString(16), Bytes.ALIGN.ALIGN_RIGHT));
        return Bytes.concat(Bytes.fromInt(privateKey.getModulus().bitLength(), 4, Bytes.ENDIAN.LITTLE_ENDIAN), hex);
    }

    /**
     * 将私钥16进制数据解析成RSAPrivateCrtKey类对象
     *
     * @param hex
     * @return
     */
    public static RSAPrivateCrtKey hex2RSAPrivateKey(String hex) {
        RSAPrivateCrtKey privateKey = null;
        try {
            byte[] hexData = Bytes.fromHexString(hex);
            byte[] tmp;
            int index = 0;
            // 私钥bits
            int bits;
            tmp = Bytes.subBytes(hexData, 0, 4);
            index += 4;
            bits = (tmp[0] & 0xFF) * 256 * 256 + (tmp[1] & 0xFF) * 256 + (tmp[2] & 0xFF);
            // 私钥modulus
            tmp = Bytes.subBytes(hexData, index, bits / 8);
            index += bits / 8;
            BigInteger modulus = new BigInteger(Bytes.toHexString(tmp), 16);
            // 公钥Exponent
            tmp = Bytes.subBytes(hexData, index, bits / 8);
            index += bits / 8;
            BigInteger publicExponent = new BigInteger(Bytes.toHexString(tmp), 16);
            // 私钥Exponent
            tmp = Bytes.subBytes(hexData, index, bits / 8);
            index += bits / 8;
            BigInteger privateExponent = new BigInteger(Bytes.toHexString(tmp), 16);
            // 私钥prime
            byte[][] buf = new byte[2][];
            tmp = Bytes.subBytes(hexData, index, bits / 16);
            index += bits / 16;
            buf[0] = tmp;
            // primeP
            BigInteger primeP = new BigInteger(Bytes.toHexString(buf[0]), 16);
            tmp = Bytes.subBytes(hexData, index, 128);
            index += bits / 16;
            buf[1] = tmp;
            // primeQ
            BigInteger primeQ = new BigInteger(Bytes.toHexString(buf[1]), 16);
            // 私钥primeExponent
            buf = new byte[2][];
            tmp = Bytes.subBytes(hexData, index, bits / 16);
            index += bits / 16;
            buf[0] = tmp;
            BigInteger primeExponentP = new BigInteger(Bytes.toHexString(buf[0]), 16);
            tmp = Bytes.subBytes(hexData, index, bits / 16);
            index += bits / 16;
            buf[1] = tmp;
            BigInteger primeExponentQ = new BigInteger(Bytes.toHexString(buf[1]), 16);
            // 私钥coefficient
            tmp = Bytes.subBytes(hexData, index, bits / 16);
            index += bits / 16;
            BigInteger coefficient = new BigInteger(Bytes.toHexString(tmp), 16);
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP,
                    primeQ, primeExponentP, primeExponentQ, coefficient);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * 公钥转PEM(PKCS1格式)
     *
     * @param publicKey
     * @return
     */
    public static String publicKey2PEMByPKCS1(RSAPublicKey publicKey) {
        return Bytes.toPEMString("RSA PUBLIC KEY", publicKey2PKCS1(publicKey));
    }

    /**
     * 私钥转PEM(PKCS1格式)
     *
     * @param privateKey
     * @return
     */
    public static String privateKey2PEMByPKCS1(RSAPrivateCrtKey privateKey) {
        return Bytes.toPEMString("RSA PRIVATE KEY", privateKey2PKCS1(privateKey));
    }

    /**
     * 公钥转PEM(PKCS8格式)
     *
     * @param publicKey
     * @return
     */
    public static String publicKey2PEMByPKCS8(RSAPublicKey publicKey) {
        return Bytes.toPEMString("RSA PUBLIC KEY", publicKey2PKCS8(publicKey));
    }

    /**
     * 私钥转PEM(PKCS8格式)
     *
     * @param privateKey
     * @return
     */
    public static String privateKey2PEMByPKCS8(RSAPrivateCrtKey privateKey) {
        return Bytes.toPEMString("RSA PRIVATE KEY", privateKey2PKCS8(privateKey));
    }

    /**
     * 公钥转PKCS1
     *
     * @param publicKey
     * @return
     */
    public static byte[] publicKey2PKCS1(RSAPublicKey publicKey) {
        byte[] pkcs1;
        if (publicKey.getPublicExponent() != null) {
            byte[] exponent = publicKey.getPublicExponent().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(exponent.length), exponent);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00});
        }
        if (publicKey.getModulus() != null) {
            byte[] modulus = publicKey.getModulus().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(modulus.length), modulus, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00});
        }
        pkcs1 = Bytes.concat(new byte[]{0x30}, Bytes.getDERLen(pkcs1.length), pkcs1);
        return pkcs1;
    }

    /**
     * 私钥转PKCS1
     *
     * @param privateKey
     * @return
     */
    public static byte[] privateKey2PKCS1(RSAPrivateCrtKey privateKey) {
        byte[] pkcs1 = null;
        if (privateKey.getCrtCoefficient() != null) {
            byte[] coefficient = privateKey.getCrtCoefficient().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(coefficient.length), coefficient);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00});
        }
        if (privateKey.getPrimeExponentQ() != null) {
            byte[] primeExponentQ = privateKey.getPrimeExponentQ().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(primeExponentQ.length), primeExponentQ, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getPrimeExponentP() != null) {
            byte[] primeExponentP = privateKey.getPrimeExponentP().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(primeExponentP.length), primeExponentP, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getPrimeQ() != null) {
            byte[] primeQ = privateKey.getPrimeQ().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(primeQ.length), primeQ, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getPrimeP() != null) {
            byte[] primeP = privateKey.getPrimeP().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(primeP.length), primeP, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getPrivateExponent() != null) {
            byte[] privateExponent = privateKey.getPrivateExponent().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(privateExponent.length), privateExponent, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getPublicExponent() != null) {
            byte[] publicExponent = privateKey.getPublicExponent().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(publicExponent.length), publicExponent, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        if (privateKey.getModulus() != null) {
            byte[] modulus = privateKey.getModulus().toByteArray();
            pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(modulus.length), modulus, pkcs1);
        } else {
            pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        }
        // Version
        pkcs1 = Bytes.concat(new byte[]{0x02, 0x01, 0x00}, pkcs1);
        pkcs1 = Bytes.concat(new byte[]{0x30}, Bytes.getDERLen(pkcs1.length), pkcs1);
        return pkcs1;
    }

    /**
     * 公钥转PKCS8
     *
     * @param publicKey
     * @returnK
     */
    public static byte[] publicKey2PKCS8(RSAPublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * 私钥转PKCS8
     *
     * @param privateKey
     * @return
     */
    public static byte[] privateKey2PKCS8(RSAPrivateCrtKey privateKey) {
        return privateKey.getEncoded();
    }


    /**
     * 验证签名数据
     *
     * @param publicKey
     * @param data
     * @param sign
     * @param signAlg
     * @return
     * @throws Exception
     */
    public static boolean verifySign(RSAPublicKey publicKey, byte[] data, byte[] sign, String signAlg) {
        boolean verify = false;
        try {
            Signature signature = Signature.getInstance(signAlg);
            signature.initVerify(publicKey);
            signature.update(data);
            verify = signature.verify(sign);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return verify;
    }

    /**
     * 验证证书链
     *
     * @param root
     * @param certs
     * @return
     */
    public static boolean verifyChain(X509Certificate root, X509Certificate... certs) {
        try {
            // 颁发者
            Set<String> issuers = new HashSet<String>();
            // 默认添加Root
            issuers.add(root.getSubjectDN().getName().trim());
            // 所有者
            Set<String> subjects = new HashSet<String>();
            // 校验日期有效期
            root.checkValidity();
            for (X509Certificate cert : certs) {
                cert.checkValidity();
                issuers.add(cert.getIssuerDN().getName().trim());
                subjects.add(cert.getSubjectDN().getName().trim());
            }
            // 叶子证书（最后节点的工作证书）
            List<X509Certificate> leafCerts = new ArrayList<X509Certificate>();
            for (X509Certificate cert : certs) {
                if (!issuers.contains(cert.getSubjectDN().getName().trim())) {
                    leafCerts.add(cert);
                }
            }
            for (X509Certificate leafCert : leafCerts) {
                if (!verifyChain(root, leafCert, certs)) {
                    return false;
                }
            }
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * 验证证书链
     *
     * @param root
     * @param leafCert
     * @param certs
     * @return
     */
    private static boolean verifyChain(X509Certificate root, X509Certificate leafCert, X509Certificate... certs) {
        try {
            X509Certificate superCert = null;
            for (X509Certificate cert : certs) {
                if (leafCert.getIssuerDN().getName().trim().equals(cert.getSubjectDN().getName().trim())) {
                    superCert = cert;
                    break;
                }
            }
            if (superCert == null) {
                if (leafCert.getIssuerDN().getName().trim().equals(root.getSubjectDN().getName().trim())) {
                    // 用Root证书验证
                    PublicKey publickey = root.getPublicKey();
                    leafCert.verify(publickey);
                } else {
                    //未找到对应的证书链校验
                    return false;
                }
            } else {
                // 验证证书链
                PublicKey publickey = superCert.getPublicKey();
                leafCert.verify(publickey);
                return verifyChain(root, superCert, certs);
            }
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
                | SignatureException e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     * 16进制转ECC公钥
     *
     * @param eccCurve
     * @param hex
     * @return
     */
    public static ECPublicKey hex2ECPublicKey(AlgUtil.ECCCurve eccCurve, String hex) {
        ECPublicKey publicKey = null;
        try {
            byte[] point = Bytes.fromHexString(hex);
            if (point[0] != 0x04) {
                throw new InvalidKeyException("EC uncompressed point indicator with byte value 04 missing");
            }
            ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(eccCurve.getName());
            ECPublicKeySpec keySpec = new ECPublicKeySpec(parameterSpec.getCurve().decodePoint(point),
                    parameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
            publicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }


    /**
     * 16进制转ECC私钥
     *
     * @param eccCurve
     * @param hex
     * @return
     */
    public static ECPrivateKey hex2ECPrivateKey(AlgUtil.ECCCurve eccCurve, String hex) {
        ECPrivateKey privateKey = null;
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(eccCurve.getName());
        BigInteger s = new BigInteger(hex, 16);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, ecParameterSpec);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
            privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * EC公钥转16进制
     *
     * @param publicKey
     * @return
     */
    public static byte[] ECPublicKey2Hex(ECPublicKey publicKey) {
        int keySize = publicKey.getParams().getCurve().getField().getFieldSize() / 8;
        byte[] data = publicKey.getEncoded();
        if (keySize % 2 != 0) {
            keySize++;
        }
        return Bytes.subBytes(data, data.length - (1 + keySize * 2));
    }

    /**
     * EC私钥转16进制
     *
     * @param privateKey
     * @return
     */
    public static byte[] ECPrivateKey2Hex(ECPrivateKey privateKey) {
        return Bytes.fromHexString(privateKey.getS().toString(16), Bytes.ALIGN.ALIGN_RIGHT);
    }

    /**
     * 公钥转PEM(PKCS8格式)
     *
     * @param publicKey
     * @return
     */
    public static String publicKey2PEMByPKCS8(ECPublicKey publicKey) {
        return Bytes.toPEMString("EC PUBLIC KEY", publicKey2PKCS8(publicKey));
    }

    /**
     * 私钥转PEM(PKCS8格式)
     *
     * @param privateKey
     * @return
     */
    public static String privateKey2PEMByPKCS8(ECPrivateKey privateKey) {
        return Bytes.toPEMString("EC PRIVATE KEY", privateKey2PKCS8(privateKey));
    }


    /**
     * 公钥转PKCS8
     *
     * @param publicKey
     * @returnK
     */
    public static byte[] publicKey2PKCS8(ECPublicKey publicKey) {
        return publicKey.getEncoded();
    }

    /**
     * 私钥转PKCS8
     *
     * @param privateKey
     * @return
     */
    public static byte[] privateKey2PKCS8(ECPrivateKey privateKey) {
        return privateKey.getEncoded();
    }


    /**
     * 签名算法
     */
    public enum SignatureAlgorithm {

        SHA256withRSA("SHA256withRSA"),
        SHA384withRSA("SHA384withRSA"),
        SHA512withRSA("SHA512withRSA"),
        SHA256withECDSA("SHA256withECDSA"),
        SHA384withECDSA("SHA384withECDSA"),
        SHA512withECDSA("SHA512withECDSA");

        private String name;

        private SignatureAlgorithm(final String name) {
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
     * 获得CSR PEM格式
     *
     * @param CN         域名
     * @param OU         部门/单位
     * @param O          组织/公司
     * @param L          城市
     * @param ST         省份
     * @param C          国家
     * @param email      邮箱
     * @param algorithm
     * @param privateKey
     * @param publicKey
     * @return
     */
    public static byte[] getCSRPEM(String CN, String OU, String O, String L, String ST, String C, String email,
                                   SignatureAlgorithm algorithm, PrivateKey privateKey, PublicKey publicKey) {
        byte[] csr = null;
        try {
            String content = "CN=" + CN;
            if (!Strings.isNullOrEmpty(OU)) {
                content += "," + "OU=" + OU;
            }
            if (!Strings.isNullOrEmpty(O)) {
                content += "," + "O=" + O;
            }
            if (!Strings.isNullOrEmpty(L)) {
                content += "," + "L=" + L;
            }
            if (!Strings.isNullOrEmpty(ST)) {
                content += "," + "ST=" + ST;
            }
            if (!Strings.isNullOrEmpty(C)) {
                content += "," + "C=" + C;
            }
            if (!Strings.isNullOrEmpty(email)) {
                content += "," + "EMAILADDRESS=" + email;
            }
            X500Principal subject = new X500Principal(content);
            ContentSigner signGen = new JcaContentSignerBuilder(algorithm.getName()).build(privateKey);
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
            PKCS10CertificationRequest csrRequest = builder.build(signGen);
            return csrRequest.getEncoded();
        } catch (OperatorCreationException | IOException e) {
            e.printStackTrace();
        }
        return csr;
    }
}
