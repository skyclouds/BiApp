package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.key.Exportability;
import com.biapp.key.KeyAlgorithm;
import com.biapp.key.KeyUsage;
import com.biapp.key.ModelOfUse;
import com.biapp.key.TR31;
import com.biapp.util.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import aura.data.Bytes;

@RunWith(AndroidJUnit4.class)
public class TR31Test {

    @Test
    public void tdesTest() {
        String key = "11111111111111111111111111111111";
        String tk = "22222222222222222222222222222222";
        TR31 tr31 = new TR31();
        byte[] pack = tr31.setKey(Bytes.fromHexString(key))
                .setKeyAlgorithm(KeyAlgorithm.TDEA)
                .setKeyUsage(KeyUsage.SYMMETRIC_KEY_DATA_ENCRYPTION)
                .setModeOfUse(ModelOfUse.DEC_OR_UNWRAP_ONLY)
                .setExportability(Exportability.NON_EXPORTABLE)
                .pack(Bytes.fromHexString(tk));
        PrintfUtil.d("pack", Bytes.toHexString(pack));
        tr31.unpack(pack, Bytes.fromHexString(tk));
    }

    @Test
    public void aesTest() {
        String key = "11111111111111111111111111111111";
        String tk = "22222222222222222222222222222222";
        TR31 tr31 = new TR31();
        byte[] pack = tr31.setKey(Bytes.fromHexString(key))
                .setKeyAlgorithm(KeyAlgorithm.AES)
                .setKeyUsage(KeyUsage.SYMMETRIC_KEY_DATA_ENCRYPTION)
                .setModeOfUse(ModelOfUse.DEC_OR_UNWRAP_ONLY)
                .setExportability(Exportability.NON_EXPORTABLE)
                .pack(Bytes.fromHexString(tk));
        PrintfUtil.d("pack", Bytes.toHexString(pack));
        tr31.unpack(pack, Bytes.fromHexString(tk));
    }
}