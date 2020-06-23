package com.biapp.utils;

import com.biapp.utils.TLVUtil.TLV;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import aura.data.Bytes;

/**
 * @author yun
 */
public class CertUtil {

    /**
     * PEM格式证书转X509Certificate
     * @param pem
     * @return
     */
    public static X509Certificate pem2Cert(String pem){
        pem=pem.replaceAll("\r|\n", "");
        if(pem.startsWith("-----BEGIN CERTIFICATE-----")&&pem.endsWith("-----END CERTIFICATE-----")){
            pem = pem.replace("-----BEGIN CERTIFICATE-----", "");
            pem = pem.replace("-----END CERTIFICATE-----", "");
            pem = FormatUtil.removeAllSpace(pem);
            return getCertificate(Bytes.fromBase64String(pem));
        }
        else {
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
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            publicKey = (RSAPublicKey) cert.getPublicKey();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
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
            pem=pem.replaceAll("\r|\n", "");
            if (pem.startsWith("-----BEGIN RSA PUBLIC KEY-----") && pem.endsWith("-----END RSA PUBLIC KEY-----")) {
                // PKCS1格式
                pem = pem.replace("-----BEGIN RSA PUBLIC KEY-----", "");
                pem = pem.replace("-----END RSA PUBLIC KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs1 = Bytes.fromBase64String(pem);
                List<TLV> tls = TLVUtil.parseDER(pkcs1);
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
                List<TLV> tls = TLVUtil.parseDER(pkcs8);
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
            pem=pem.replaceAll("\r|\n", "");
            if (pem.startsWith("-----BEGIN RSA PRIVATE KEY-----") && pem.endsWith("-----END RSA PRIVATE KEY-----")) {
                // PKCS1格式
                pem = pem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
                pem = pem.replace("-----END RSA PRIVATE KEY-----", "");
                pem = FormatUtil.removeAllSpace(pem);
                byte[] pkcs1 = Bytes.fromBase64String(pem);
                List<TLV> tls = TLVUtil.parseDER(pkcs1);
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
                List<TLV> tls = TLVUtil.parseDER(pkcs8);
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
            tmp = Bytes.subBytes(hexData, index, 256);
            index += 256;
            BigInteger modulus = new BigInteger(Bytes.toHexString(tmp), 16);
            // 公钥exponent
            tmp = Bytes.subBytes(hexData, index, 256);
            index += 256;
            BigInteger exponent = new BigInteger(Bytes.toHexString(tmp), 16);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
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
            tmp = Bytes.subBytes(hexData, index, 256);
            index += 256;
            BigInteger modulus = new BigInteger(Bytes.toHexString(tmp), 16);
            // 公钥Exponent
            tmp = Bytes.subBytes(hexData, index, 256);
            index += 256;
            BigInteger publicExponent = new BigInteger(Bytes.toHexString(tmp), 16);
            // 私钥Exponent
            tmp = Bytes.subBytes(hexData, index, 256);
            index += 256;
            BigInteger privateExponent = new BigInteger(Bytes.toHexString(tmp), 16);
            // 私钥prime
            byte[][] buf = new byte[2][];
            tmp = Bytes.subBytes(hexData, index, 128);
            index += 128;
            buf[0] = tmp;
            // primeP
            BigInteger primeP = new BigInteger(Bytes.toHexString(buf[0]), 16);
            tmp = Bytes.subBytes(hexData, index, 128);
            index += 128;
            buf[1] = tmp;
            // primeQ
            BigInteger primeQ = new BigInteger(Bytes.toHexString(buf[1]), 16);
            // 私钥primeExponent
            buf = new byte[2][];
            tmp = Bytes.subBytes(hexData, index, 128);
            index += 128;
            buf[0] = tmp;
            BigInteger primeExponentP = new BigInteger(Bytes.toHexString(buf[0]), 16);
            tmp = Bytes.subBytes(hexData, index, 128);
            index += 128;
            buf[1] = tmp;
            BigInteger primeExponentQ = new BigInteger(Bytes.toHexString(buf[1]), 16);
            // 私钥coefficient
            tmp = Bytes.subBytes(hexData, index, 128);
            index += 128;
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
        String pem = "";
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----BEGIN RSA PUBLIC KEY-----");
        buffer.append(System.lineSeparator());
        buffer.append(Bytes.toBase64String(publicKey2PKCS1(publicKey)));
        buffer.append(System.lineSeparator());
        buffer.append("-----END RSA PUBLIC KEY-----");
        pem = buffer.toString();
        return pem;
    }

    /**
     * 私钥转PEM(PKCS1格式)
     *
     * @param privateKey
     * @return
     */
    public static String privateKey2PEMByPKCS1(RSAPrivateCrtKey privateKey) {
        String pem = "";
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----BEGIN RSA PRIVATE KEY-----");
        buffer.append(System.lineSeparator());
        buffer.append(Bytes.toBase64String(privateKey2PKCS1(privateKey)));
        buffer.append(System.lineSeparator());
        buffer.append("-----END RSA PRIVATE KEY-----");
        pem = buffer.toString();
        return pem;
    }

    /**
     * 公钥转PEM(PKCS8格式)
     *
     * @param publicKey
     * @return
     */
    public static String publicKey2PEMByPKCS8(RSAPublicKey publicKey) {
        String pem = "";
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----BEGIN PUBLIC KEY-----");
        buffer.append(System.lineSeparator());
        buffer.append(Bytes.toBase64String(publicKey2PKCS8(publicKey)));
        buffer.append(System.lineSeparator());
        buffer.append("-----END PUBLIC KEY-----");
        pem = buffer.toString();
        return pem;
    }

    /**
     * 私钥转PEM(PKCS8格式)
     *
     * @param privateKey
     * @return
     */
    public static String privateKey2PEMByPKCS8(RSAPrivateCrtKey privateKey) {
        String pem = "";
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----BEGIN PRIVATE KEY-----");
        buffer.append(System.lineSeparator());
        buffer.append(Bytes.toBase64String(privateKey2PKCS8(privateKey)));
        buffer.append(System.lineSeparator());
        buffer.append("-----END PRIVATE KEY-----");
        pem = buffer.toString();
        return pem;
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
     * 签名数据
     *
     * @param privateKey
     * @param data
     * @param signAlg
     * @return
     * @throws Exception
     */
    public static byte[] sign(RSAPrivateKey privateKey, byte[] data, String signAlg) {
        byte[] sign = null;
        try {
            Signature signature = Signature.getInstance(signAlg);
            signature.initSign(privateKey);
            signature.update(data);
            sign = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return sign;
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
     * @param rootCertificate
     * @param collectionX509CertificateChain
     * @return
     */
    public static boolean verifyChain(X509Certificate rootCertificate,
                                      ArrayList<X509Certificate> collectionX509CertificateChain) {
        // Sort certificate chain
        ArrayList<X509Certificate> tempCertificateChain = new ArrayList<>();
        tempCertificateChain.add(rootCertificate);
        while (tempCertificateChain.size() <= collectionX509CertificateChain.size()) {

            X509Certificate subCert = null;
            for (X509Certificate cert : collectionX509CertificateChain) {
                if (tempCertificateChain.get(tempCertificateChain.size() - 1).getSubjectDN()
                        .equals(cert.getIssuerDN())) {
                    subCert = cert;
                }
            }
            if (subCert != null) {
                tempCertificateChain.add(subCert);
            } else {
                return false;
            }
        }
        tempCertificateChain.remove(rootCertificate);

        // convert the certificate chain to an array
        X509Certificate[] arX509certificate = new X509Certificate[tempCertificateChain.size()];
        tempCertificateChain.toArray(arX509certificate);

        // From top to bottom along the certificate chain, verify that the owner of the
        // certificate is the issuer of the next certificate
        Principal principalLast = null;
        for (int i = 0; i < arX509certificate.length; i++) {
            // Traverse ArX509Certificate
            X509Certificate x509Certificate = arX509certificate[i];
            // get publisher id
            Principal principalIssuer = x509Certificate.getIssuerDN();
            // obtain the subject id of the certificate
            Principal principalSubject = x509Certificate.getSubjectDN();

            if (principalLast != null) {
                // The issuer of the verification certificate is the owner of the previous
                // certificate
                if (!principalIssuer.equals(principalLast)) {
                    return false;
                }

                try {
                    // get the public key of the last certificate
                    PublicKey publickey = arX509certificate[i - 1].getPublicKey();
                    // Verify that the certificate has been signed with the private key
                    // corresponding to the specified public key
                    arX509certificate[i].verify(publickey);
                } catch (Exception e) {
                    return false;
                }
            }
            principalLast = principalSubject;

        }

        // Prove that the first certificate in the certificate chain is issued by a CA
        // that the user trusts
        try {
            PublicKey publickey = rootCertificate.getPublicKey();
            arX509certificate[0].verify(publickey);
        } catch (Exception e) {
            return false;
        }

        // Verify that each certificate in the certificate chain is within the validity
        // period
        Date date = new Date();
        for (int i = 0; i < arX509certificate.length; i++) {
            try {
                arX509certificate[i].checkValidity(date);
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

}
