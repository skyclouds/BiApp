package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.utils.AlgUtil;
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
}