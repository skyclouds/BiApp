package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.key.Exportability;
import com.biapp.key.KeyAlgorithm;
import com.biapp.key.KeyBlockVersion;
import com.biapp.key.KeyUsage;
import com.biapp.key.ModeOfUse;
import com.biapp.key.OptionalBlock;
import com.biapp.key.OptionalBlockID;
import com.biapp.key.TR31;
import com.biapp.key.VerNum;
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
                .setModeOfUse(ModeOfUse.DEC_OR_UNWRAP_ONLY)
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
                .setModeOfUse(ModeOfUse.DEC_OR_UNWRAP_ONLY)
                .setExportability(Exportability.NON_EXPORTABLE)
                .pack(Bytes.fromHexString(tk));
        PrintfUtil.d("pack", Bytes.toHexString(pack));
        tr31.unpack(pack, Bytes.fromHexString(tk));
    }

    @Test
    public void unpack() {
        byte[] pack = Bytes.fromHexString("42303130344231545830304E303130304B533138333434344231344133424242344136423434343138374639373934464331303943333937314635304531463433453142393733383038393741444630363043383244303644384131433132423135303835393930");
        byte[] tk = Bytes.fromHexString("000000000000000000000000000000000000000000000000");
        TR31 tr31 = new TR31();
        tr31.unpack(pack, tk);
    }

    @Test
    public void versionATest() {
        byte[] pack = new TR31().setKeyBlockVersion(KeyBlockVersion.A)
                .setKey(Bytes.fromHexString("EDB380DD340BC2620247D445F5B8D678"))
                .setKeyAlgorithm(KeyAlgorithm.TDEA)
                .setKeyUsage(KeyUsage.KEY_ENC_OR_WRAP)
                .setModeOfUse(ModeOfUse.DEC_OR_UNWRAP_ONLY)
                .setVerNum("12")
                .setExportability(Exportability.SENSITIVE)
                .addOptionalBlock(OptionalBlockID.KS, new OptionalBlock("00604B120F9292800000"))
                .setKeyBlockRandom(Bytes.fromHexString("8546A8ED98D1"))
                .pack(Bytes.fromHexString("B8ED59E0A279A295E9F5ED7944FD06B9"));

        PrintfUtil.d("VersionA", Bytes.toHexString(pack));
        new TR31().unpack(pack, Bytes.fromHexString("B8ED59E0A279A295E9F5ED7944FD06B9"));

        pack = new TR31().setKeyBlockVersion(KeyBlockVersion.A)
                .setKey(Bytes.fromHexString("F039121BEC83D26B169BDCD5B22AAF8F"))
                .setKeyAlgorithm(KeyAlgorithm.TDEA)
                .setKeyUsage(KeyUsage.PIN_ENCRYPTION)
                .setModeOfUse(ModeOfUse.ENC_OR_WRAP_ONLY)
                .setVerNum(VerNum.NONE)
                .setExportability(Exportability.EXPORTABLE_UNDER_KEK)
                .setKeyBlockRandom(Bytes.fromHexString("720DF563BB07"))
                .pack(Bytes.fromHexString("89E88CF7931444F334BD7547FC3F380C"));

        PrintfUtil.d("VersionA", Bytes.toHexString(pack));
        new TR31().unpack(pack, Bytes.fromHexString("89E88CF7931444F334BD7547FC3F380C"));
    }

    @Test
    public void versionCTest() {
        byte[] pack = new TR31().setKeyBlockVersion(KeyBlockVersion.C)
                .setKey(Bytes.fromHexString("EDB380DD340BC2620247D445F5B8D678"))
                .setKeyAlgorithm(KeyAlgorithm.TDEA)
                .setKeyUsage(KeyUsage.BDK)
                .setModeOfUse(ModeOfUse.DERIVE_KEYS)
                .setVerNum("12")
                .setExportability(Exportability.SENSITIVE)
                .addOptionalBlock(OptionalBlockID.KS, new OptionalBlock("00604B120F9292800000"))
                .setKeyBlockRandom(Bytes.fromHexString("8546A8ED98D1"))
                .pack(Bytes.fromHexString("B8ED59E0A279A295E9F5ED7944FD06B9"));

        PrintfUtil.d("VersionC", Bytes.toHexString(pack));
        new TR31().unpack(pack, Bytes.fromHexString("B8ED59E0A279A295E9F5ED7944FD06B9"));
    }
}