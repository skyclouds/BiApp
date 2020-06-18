package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.utils.AlgUtils;
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
        byte[] encrypt= AlgUtils.encrypt(AlgUtils.SymmetryAlgorithm.RC2, AlgUtils.AlgorithmModel.CBC,
                AlgUtils.SymmetryPadding.PKCS5Padding, key, iv, data);
        PrintfUtil.d("encrypt",Bytes.toHexString(encrypt));
        PrintfUtil.d("data",Bytes.toHexString(AlgUtils.decrypt(AlgUtils.SymmetryAlgorithm.RC2,
         AlgUtils.AlgorithmModel.CBC,
        AlgUtils.SymmetryPadding.PKCS5Padding, key, iv, encrypt)));
        PrintfUtil.d("hash",Bytes.toHexString(AlgUtils.hash(AlgUtils.HashAlgorithm.SHA256,data)));
        PrintfUtil.d("mac",Bytes.toHexString(AlgUtils.mac(AlgUtils.MACAlgorithm.HmacSHA256,key,data)));
    }
}