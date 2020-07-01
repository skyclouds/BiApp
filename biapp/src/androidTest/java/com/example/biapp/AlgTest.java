package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.utils.AlgUtil;
import com.biapp.utils.CertUtil;
import com.biapp.utils.PrintfUtil;

import org.junit.runner.RunWith;

import aura.data.Bytes;


@RunWith(AndroidJUnit4.class)
public class AlgTest {
    public static void main(String[] args) {
        // LogUtil.setShowCompileInfo(true);
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

    public static void billTest() {
        String pem = "-----BEGIN PUBLIC KEY-----"
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA30S5TQieACF5PpnlVnlCN4CDp7cuB29aN7b6Ekv6Uu9+ixm9ydnAJ6LeouKKO/fhuPbP24WVO1yEQvsxw3UFxG0Zv7+kJqANMgq4sJAIhw8nNcOFQFk0Z7R4ROzrMZKv88AQ3X5IGbHZXodzY2S5kj4rJ3LxIa0Vq7vA2uu4nOiojh1epru3Dw3ooOp0FLax0EwcltBhEGOeDmS+BQXI5wsHYaWEFSEcq8OoqByC52RXx+emiK3aZdFCwbBssgH/klXjS/SOmBTaOd9sJRcjVTlGKV0k/ZR88edcSQYKqEpYDTSO/LPHKa4r9bDB6N6Y53xRTAHQFfh0gWRlDSBkqQIDAQAB"
                + "-----END PUBLIC KEY-----";
        String deviceKey = "Dnc67kcPL0kE6lSkcKtbJj4wgY5VOeKbuOzhy6/YhLWntP5xG8p4Smi4Vv9T65a0XfxhpJJ2mcroPaGInW6ynb5CLQClwoUgiQuLko+WLpTUscLRIwyz+Os/9eUsP0ccE+Y3thdVjxWMfSD8LA7jk45sUdVHmqdFRBkbfNCCTL8=";
        String responseCode = "00";
        String responseMsg = "success";
        String resAuthorCode = "deviceKey=" + deviceKey + "&responseCode=" + responseCode + "&responseMsg="
                + responseMsg;
        String sign = "AdpRr/Furc2h7YQv/PLfk1BC79UuGGmr/Q7rroSUJ2u54aNdq3dSMFuJJV2/otPCTd1P47DoHoWACEyS0iGp+S54inPJ8nwiy/ItDX3LgDDTIFARSJruFGzzmO63adqi6O6ujo1Qcngu2UPnFq4YfcijY5DplQV9ikx+r3ihBC7pBgcL0UEyh59k80IQYubQIQigkGWpvrw9Qp0e2iqP9O+C2vVrmQa6MoyQZQ+fe+kkFzU+C+3P0Y/P2PxAcj60KOw2fQFJpzOPrnsSsIhQHGLlBPufVcxlx4yIYIKh64SqzWoeqLOkbXYeP2tAkwhoSWEpdCW0CiLf3oj9Inq+VA==";
        String data = Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.MD5, resAuthorCode.getBytes()));
        PrintfUtil.d("data", data);
        PrintfUtil.d("verify", CertUtil.verifySign(CertUtil.pem2RSAPublicKey(pem), data.getBytes(),
                Bytes.fromBase64String(sign), "SHA1WithRSA") + "");
    }
}