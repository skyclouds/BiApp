package com.biapp.util;

import com.biapp.util.TLVUtil.TLV;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import aura.data.Bytes;

/**
 * @author yun
 */
public class CertUtil {

    // 增加BouncyCastle
    private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        Security.insertProviderAt(BOUNCY_CASTLE_PROVIDER, 1);
    }

    /***
     * X.509证书结构 X.509证书结构长度+证书长度+证书信息(1 证书版本信息 2 证书序列号 3 签名算法描述 4 证书颁发者信息 5 有效期信息 6
     * 主题信息 7 公钥信息 8 扩展信息)+签名算法信息+签名信息
     */
    public static class X509RSACert {

        /**
         * 扩展域标签
         */
        public enum ExtendTAG {
            /**
             * 密钥用途
             */
            KEY_USAGE(new byte[]{0x55, 0x1D, 0x0F}),
            /**
             * 签名方式
             */
            SIGN_MODE(new byte[]{0x55, 0x1D, 0x67}),
            /**
             * 原始文件HASH值
             */
            FILE_HASH(new byte[]{0x55, 0x1D, (byte) 0xA0}),
            /**
             * 证书文件名
             */
            CRT_NAME(new byte[]{0x55, 0x1D, 0x61}),
            /**
             * 上级证书ID
             */
            UPPER_CRT_ID(new byte[]{0x55, 0x1D, 0x62}),
            /**
             * 组号
             */
            GROUP_ID(new byte[]{0x55, 0x1D, 0x63}),
            /**
             * 组内号
             */
            GROUP_INSIDE_ID(new byte[]{0x55, 0x1D, 0x64}),
            /**
             * 证书级别
             */
            CERT_LEVEL(new byte[]{0x55, 0x1D, 0x65}),
            /**
             * 是否可替换联迪默认根证书
             */
            IF_REPLACE_DF_CRT(new byte[]{0x55, 0x1D, 0x66}),
            /**
             * 证书版本
             */
            CERT_VER(new byte[]{0x55, 0x1D, 0x68});

            private byte[] value;

            private ExtendTAG(final byte[] value) {
                this.value = value;
            }

            public byte[] getValue() {
                return value;
            }

            public void setValue(byte[] value) {
                this.value = value;
            }
        }

        /**
         * 证书数据
         */
        private byte[] data;

        /**
         * 版本信息
         */
        private int version;

        /**
         * 序列号
         */
        private String serialNumber;

        /**
         * 签名算法名称
         */
        private String signAlgName;

        /**
         * 颁发者名称
         */
        private String issuerName;

        /**
         * 开始时间
         */
        private long startTime;
        /**
         * 结束时间
         */
        private long endTime;

        /**
         * 主题名称
         */
        private String subjectName;

        /**
         * 公钥
         */
        private RSAPublicKey publicKey;

        /**
         * 签名信息
         */
        private byte[] signature;

        /**
         * X509数据项信息
         */
        private List<TLV> x509Items;

        /**
         * 扩展信息
         */
        private List<TLV> extend;


        public X509RSACert(byte[] data) {
            parse(data);
        }

        public byte[] getData() {
            return data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }

        public int getVersion() {
            return version;
        }

        public void setVersion(int version) {
            this.version = version;
        }

        public String getSerialNumber() {
            return serialNumber;
        }

        public void setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
        }

        public String getSignAlgName() {
            return signAlgName;
        }

        public void setSignAlgName(String signAlgName) {
            this.signAlgName = signAlgName;
        }

        public String getIssuerName() {
            return issuerName;
        }

        public void setIssuerName(String issuerName) {
            this.issuerName = issuerName;
        }

        public long getStartTime() {
            return startTime;
        }

        public void setStartTime(long startTime) {
            this.startTime = startTime;
        }

        public long getEndTime() {
            return endTime;
        }

        public void setEndTime(long endTime) {
            this.endTime = endTime;
        }

        public String getSubjectName() {
            return subjectName;
        }

        public void setSubjectName(String subjectName) {
            this.subjectName = subjectName;
        }

        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(RSAPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public List<TLV> getX509Items() {
            return x509Items;
        }

        public void setX509Items(List<TLV> x509Items) {
            this.x509Items = x509Items;
        }

        public List<TLV> getExtend() {
            return extend;
        }

        public void setExtend(List<TLV> extend) {
            this.extend = extend;
        }

        public byte[] getSignature() {
            return signature;
        }

        public void setSignature(byte[] signature) {
            this.signature = signature;
        }


        public byte[] getExtendValue(ExtendTAG tag) {
            byte[] value = null;
            /**
             * 0X06表示自定义标签信息 T 0x06 L 03
             */
            byte[] flag = new byte[]{0x06, 0x03};
            for (TLV tlv : extend) {
                if (Bytes.equals(tlv.getValue(), Bytes.concat(flag, tag.value), 0, flag.length + tag.value.length)) {
                    value = parseExtendValue(Bytes.subBytes(tlv.getValue(), flag.length + tag.value.length));
                }
            }
            return value;
        }

        /**
         * 解析扩展域值
         *
         * @param tlv
         * @return
         */
        private byte[] parseExtendValue(byte[] tlv) {
            /**
             * TAG 标签为0x04 0x02 0x13
             */
            if (!(tlv[0] == 0x04 || tlv[0] == 0x02 || tlv[0] == 0x13)) {
                throw new IllegalArgumentException("parse extend value error");
            }
            int lenLength = 1;
            int len = tlv[1] & 0xFF;
            if (len > 0x7F) {
                lenLength += (len & 0x7F);
                len = Bytes.toInt(Bytes.subBytes(tlv, 2, (len & 0x7F)));
            }
            byte[] value = Bytes.subBytes(tlv, 1 + lenLength, len);
            // 遇到0X02继续解析
            if ((value[0] == 0x02 || value[0] == 0x13) && value[1] != 0x00) {
                return parseExtendValue(value);
            }
            return value;
        }

        private void parse(byte[] data) {
            X509Certificate cert = CertUtil.getCertificate(data);
            if (cert != null) {
                this.data = data;
                this.version = cert.getVersion();
                this.serialNumber = cert.getSerialNumber().toString();
                //this.signAlgName=cert.getSigAlgName();
                this.issuerName = "";
                for (String value : cert.getIssuerDN().getName().split(",")) {
                    if (value.trim().startsWith("CN=")) {
                        issuerName = value.substring(value.indexOf("CN=") + "CN=".length());
                    }
                }
                this.startTime = cert.getNotBefore().getTime();
                this.endTime = cert.getNotAfter().getTime();
                this.subjectName = "";
                for (String value : cert.getSubjectDN().getName().split(",")) {
                    if (value.trim().startsWith("CN=")) {
                        subjectName = value.substring(value.indexOf("CN=") + "CN=".length());
                    }
                }
                this.publicKey = (RSAPublicKey) cert.getPublicKey();
                this.signature = cert.getSignature();

                List<TLV> tlvs = TLVUtil.parseDER(data);
                if (tlvs != null && !tlvs.isEmpty()) {
                    if (tlvs.get(0).getChildren() != null && !tlvs.get(0).getChildren().isEmpty()) {
                        TLV certInfos = tlvs.get(0).getChildren().get(0);
                        if (certInfos.getChildren() != null && !certInfos.getChildren().isEmpty() && certInfos.getChildren().size() == 8) {
                            this.extend = certInfos.getChildren().get(7).getChildren().get(0).getChildren();
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
            }
        }
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
     * 获得X509RSACert
     *
     * @param certData
     * @return
     */
    public static X509RSACert getX509RSACert(byte[] certData) {
        return new X509RSACert(certData);
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
            pem = pem.replaceAll("\r|\n", "");
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
     * RSAPublicKey类对象解析成6进制数据
     *
     * @param publicKey
     * @return
     */
    public static byte[] RSAPublicKey2Hex(RSAPublicKey publicKey) {
        byte[] hex = Bytes.concat(Bytes.fromHexString(publicKey.getModulus().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
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
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
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
        byte[] hex = Bytes.concat(Bytes.fromHexString(privateKey.getModulus().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(FormatUtil.addHead('0', privateKey.getModulus().bitLength() / 4, privateKey.getPublicExponent().toString(16))),
                Bytes.fromHexString(privateKey.getPrivateExponent().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeP().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeQ().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeExponentP().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getPrimeExponentQ().toString(16),Bytes.ALIGN.ALIGN_RIGHT),
                Bytes.fromHexString(privateKey.getCrtCoefficient().toString(16),Bytes.ALIGN.ALIGN_RIGHT));
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
            tmp = Bytes.subBytes(hexData, index, bits / 16);
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
            ECPublicKeySpec keySpec = new ECPublicKeySpec(parameterSpec.getCurve().decodePoint(point), parameterSpec);
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
        try {
            ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(eccCurve.getName());
            BigInteger s = new BigInteger(hex, 16);
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, ecParameterSpec);
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
}
