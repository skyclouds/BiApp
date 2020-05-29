package com.biapp.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;

import aura.data.Bytes;

/**
 * CertUtil
 *
 * @author yun
 */
public class CertUtil {

    /**
     * 获得证书
     *
     * @param certData
     * @return
     */
    public X509Certificate getCertificate(byte[] certData) {
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
            X509Certificate cert = (X509Certificate) certificateFactory
                    .generateCertificate(inputStream);
            publicKey = (RSAPublicKey) cert.getPublicKey();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return publicKey;
    }


    /**
     * 公钥转PEM
     *
     * @param publicKey
     * @return
     */
    public static String publickey2PEM(RSAPublicKey publicKey) {
        String pem = "";
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----BEGIN PUBLIC KEY-----");
        buffer.append(System.lineSeparator());
        buffer.append(Bytes.toBase64String(publicKey.getEncoded()));
        buffer.append("-----END PUBLIC KEY-----");
        pem = buffer.toString();
        return pem;
    }

    /**
     * 公钥转PKCS8
     *
     * @param publicKey
     * @return
     */
    public static String publickey2PKCS8(RSAPublicKey publicKey) {
        return Bytes.toHexString(publicKey.getEncoded());
    }

    /**
     * 公钥转PKCS1
     *
     * @param publicKey
     * @return
     */
    public static byte[] publickey2PKCS1(RSAPublicKey publicKey) {
        byte[] pkcs1;
        byte[] exponent = publicKey.getPublicExponent().toByteArray();
        pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(exponent.length), exponent);
        byte[] modulus = publicKey.getModulus().toByteArray();
        pkcs1 = Bytes.concat(modulus, pkcs1);
        pkcs1 = Bytes.concat(new byte[]{0x02}, Bytes.getDERLen(modulus.length), pkcs1);
        pkcs1 = Bytes.concat(new byte[]{0x30}, Bytes.getDERLen(pkcs1.length), pkcs1);
        return pkcs1;
    }

    /**
     * 验证签名数据
     *
     * @param publicKey
     * @param sign
     * @return
     * @throws Exception
     */
    public boolean verifySign(RSAPublicKey publicKey, byte[] data, byte[] sign, String signAlg) {
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
     * 验证签名数据
     *
     * @param publicKey
     * @param sign
     * @return
     * @throws Exception
     */
    public boolean verifySign(PublicKey publicKey, byte[] data, byte[] sign, String signAlg) {
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
     * @param rootCertificate
     * @param collectionX509CertificateChain
     * @return
     */
    public static boolean verifyChain(X509Certificate rootCertificate, ArrayList<X509Certificate> collectionX509CertificateChain) {
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

        //convert the certificate chain to an array
        X509Certificate[] arX509certificate = new X509Certificate[tempCertificateChain.size()];
        tempCertificateChain.toArray(arX509certificate);

        //From top to bottom along the certificate chain, verify that the owner of the certificate is the issuer of the next certificate
        Principal principalLast = null;
        for (int i = 0; i < arX509certificate.length; i++) {
            //Traverse ArX509Certificate
            X509Certificate x509Certificate = arX509certificate[i];
            //get publisher id
            Principal principalIssuer = x509Certificate.getIssuerDN();
            //obtain the subject id of the certificate
            Principal principalSubject = x509Certificate.getSubjectDN();

            if (principalLast != null) {
                //The issuer of the verification certificate is the owner of the previous certificate
                if (!principalIssuer.equals(principalLast)) {
                    return false;
                }

                try {
                    //get the public key of the last certificate
                    PublicKey publickey = arX509certificate[i - 1].getPublicKey();
                    //Verify that the certificate has been signed with the private key corresponding to the specified public key
                    arX509certificate[i].verify(publickey);
                } catch (Exception e) {
                    return false;
                }
            }
            principalLast = principalSubject;

        }

        //Prove that the first certificate in the certificate chain is issued by a CA that the user trusts
        try {
            PublicKey publickey = rootCertificate.getPublicKey();
            arX509certificate[0].verify(publickey);
        } catch (Exception e) {
            return false;
        }

        //Verify that each certificate in the certificate chain is within the validity period
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
