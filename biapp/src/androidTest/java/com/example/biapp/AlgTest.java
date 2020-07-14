package com.example.biapp;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.biapp.util.AlgUtil;
import com.biapp.util.CertUtil;
import com.biapp.util.FileUtil;
import com.biapp.util.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.interfaces.RSAPrivateCrtKey;

import aura.data.Bytes;


@RunWith(AndroidJUnit4.class)
public class AlgTest {

    @Test
    public void algTest() {
        byte[] key = new byte[16];
        byte[] iv = new byte[8];
        byte[] data = new byte[64];
        byte[] encrypt = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.RC2, AlgUtil.AlgorithmModel.CBC,
                AlgUtil.SymmetryPadding.PKCS5Padding, key, iv, data);
        PrintfUtil.d("encrypt", Bytes.toHexString(encrypt));
        PrintfUtil.d("data", Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.RC2,
                AlgUtil.AlgorithmModel.CBC,
                AlgUtil.SymmetryPadding.PKCS5Padding, key, iv, encrypt)));
        PrintfUtil.d("hash", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA256, data)));
        PrintfUtil.d("mac", Bytes.toHexString(AlgUtil.mac(AlgUtil.MACAlgorithm.HmacSHA256, key, data)));
    }

    @Test
    public void billTest() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        String pk = "57DCCA8564815AD549E45A6667E58DA9";
        String pem = "-----BEGIN PUBLIC KEY-----"
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA30S5TQieACF5PpnlVnlCN4CDp7cuB29aN7b6Ekv6Uu9+ixm9ydnAJ6LeouKKO/fhuPbP24WVO1yEQvsxw3UFxG0Zv7+kJqANMgq4sJAIhw8nNcOFQFk0Z7R4ROzrMZKv88AQ3X5IGbHZXodzY2S5kj4rJ3LxIa0Vq7vA2uu4nOiojh1epru3Dw3ooOp0FLax0EwcltBhEGOeDmS+BQXI5wsHYaWEFSEcq8OoqByC52RXx+emiK3aZdFCwbBssgH/klXjS/SOmBTaOd9sJRcjVTlGKV0k/ZR88edcSQYKqEpYDTSO/LPHKa4r9bDB6N6Y53xRTAHQFfh0gWRlDSBkqQIDAQAB"
                + "-----END PUBLIC KEY-----";
        String deviceKey = "TB+INgCqt00puZcrhb2WSbgd1tQMkZjSEGpgtprYQV0Iz5jtBpZMISc5TkwYnKt5+W1b+fjC3mlUCt5AwcsnzDN8n0ucibcE+ryxLfN4mpq+4VK82xCd4XPageGzubu1CB7XAmXw+ReadrE820dp9m0gZflhpGCotpjX1gdGf2A=";
        String encPrivateKey = Bytes.toHexString(FileUtil.toByteArray(FileUtil.readAssetsFile(context, "BillPrivateKey")));
        PrintfUtil.d("encPrivateKey", encPrivateKey);
        String privateKey = Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.AlgorithmModel.CBC, AlgUtil.SymmetryPadding.NoPadding, Bytes.fromHexString(pk), new byte[8], Bytes.subBytes(Bytes.fromHexString(encPrivateKey), 4)));
        RSAPrivateCrtKey rsaPrivateCrtKey = CertUtil.hex2RSAPrivateKey(privateKey);
        byte[] key = AlgUtil.decrypt(rsaPrivateCrtKey, AlgUtil.AsymmetricPadding.PKCS1Padding, Bytes.fromBase64String(deviceKey));
        PrintfUtil.d("key", new String(key));
        PrintfUtil.d("kcv", Bytes.toHexString(AlgUtil.tdesKCV(new String(key).getBytes())));
        String responseCode = "00";
        String responseMsg = "success";
        String resAuthorCode = "deviceKey=" + deviceKey + "&responseCode=" + responseCode + "&responseMsg="
                + responseMsg;
        String sign = "F7wqgoY2J7DxW83Ypd/ak2+32ivlnV59ADlETpggPcTHxPyAvXzGZuu2fWmzaoXOB/AAeVB9vqz6tKB80UPLKR4nCaB1L9HVAQ/LUWtJo3baLnKIIbreQ99KJ34Uchhs93P9oSmhrLsacXKTJ9fdv6NvHBlWMzEJY2SSMPotB8RgD5MEm9POn/S1p1Qovubtu2J0gXQ1Z9rkhuTImlvYuSsBD5m8Fno4pz1tQouDPLfF+82OKqTx6GtSmgZf443I25sEePHyeT7Pspt0r5Z21NZoQAbELqZU4MTWkwPW8UAzSecU1UgfZ0iBlSmg3UVIfH7nMivkNeN6yOm+FQvTAg==";
        String data = Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.MD5, resAuthorCode.getBytes()));
        PrintfUtil.d("data", data);
        PrintfUtil.d("verify", CertUtil.verifySign(CertUtil.pem2RSAPublicKey(pem), data.getBytes(),
                Bytes.fromBase64String(sign), "SHA1WithRSA") + "");
    }

    @Test
    public void ikTest() {
        byte[] ck1 = Bytes.fromHexString("11111111111111111111111111111111");
        byte[] ksn1 = Bytes.fromHexString("FFFFFF910626A4E00000");
        byte[] expect1 = Bytes.fromHexString("E9758033708B76CACDE1744D4633E164");
        byte[] ik1 = AlgUtil.tdesIK(ck1, ksn1);
        PrintfUtil.d("TDES-IK", Bytes.toHexString(ik1));
        PrintfUtil.d("TDES-IKExpect", Bytes.equals(ik1, expect1) + "");

        byte[] ck2 = Bytes.fromHexString("FEDCBA9876543210F1F1F1F1F1F1F1F1");
        byte[] ksn2 = Bytes.fromHexString("123456789012345612345678");
        byte[] expect2 = Bytes.fromHexString("1273671EA26AC29AFA4D1084127652A1");
        byte[] ik2 = AlgUtil.aesIK(ck2, ksn2);
        PrintfUtil.d("AES-IK", Bytes.toHexString(ik2));
        PrintfUtil.d("AES-IKExpect", Bytes.equals(ik2, expect2) + "");
    }

    @Test
    public void ksnAddTest() {
        String newKsn1 = AlgUtil.ksnAdd1("12345678901234567890");
        PrintfUtil.d("newKsn1", newKsn1);
        String newKsn2 = AlgUtil.ksnAdd1("123456789012345678901234");
        PrintfUtil.d("newKsn2", newKsn2);
    }

}