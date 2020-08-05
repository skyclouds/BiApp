package com.biapp.key;


import com.biapp.util.AlgUtil;
import com.biapp.util.PrintfUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import aura.data.Bytes;
import aura.data.Strings;

/**
 * TR-31包
 *
 * @author Yun
 */
public class TR31 {

    /**
     * TR31- 密文中MAC长度
     */
    public final static int TR31_TEDS_MAC_LEN = 16;

    /**
     * TR31- 密文中MAC长度
     */
    public final static int TR31_AES_MAC_LEN = 32;


    /**
     * KeyHead数据包：1字节TAG+4字节TR-31包长度+2字节keyUsage+1字节keyAlgorithm+1字节modeOfUse+2字节VerNum+1字节Exportability+2字节自定义域数量+3030+ 自定义域
     */
    private byte[] keyHead;

    /**
     * 自定义域数量
     */
    private byte[] optionalNum;

    /**
     * @see KeyBlockVersion
     * KeyBlockVersion
     */
    private byte keyBlockVersion = KeyBlockVersion.B;

    /**
     * 明文Key数据
     */
    private byte[] key;

    /**
     * 2字节明文Key数据长度
     */
    private byte[] keyLength;

    /**
     * 6字节KeyBlock随机数
     */
    private byte[] keyBlockRandom;

    /***
     * 4字节TR-31包长度,ASCII码表示
     */
    private byte[] tr31Length = {0x30, 0x30, 0x30, 0x30};

    /**
     * @see KeyUsage
     * 2字节keyUsage
     */
    private byte[] keyUsage = new byte[]{0x30, 0x30};

    /**
     * @see KeyAlgorithm
     * 1字节keyAlgorithm
     */
    private byte keyAlgorithm;

    /**
     * @see ModeOfUse
     * 1字节modeOfUse 默认0
     */
    private byte modeOfUse = 0x30;

    /**
     * 2字节VerNum,ASCII码表示
     */
    private byte[] verNum = new byte[]{0x30, 0x30};

    /**
     * @see Exportability
     * 1字节exportability
     */
    private byte exportability = 0x30;

    /**
     * 2字节KSN长度,ASCII码表示(3230或者3234)
     */
    private byte[] ksnLength;

    /**
     * TDES 20字节,AES 24字节,ASCII码表示
     */
    private String ksn = "";


    /**
     * 2字节BDK长度+BDK+填充字节随机数
     */
    private byte[] keyBlock;


    /**
     * OUT数据包：用ENCKEY对KEYBLOCK进行TEDS/AES CBC加密初始向量为MAC
     * ENCKEY：由TK用TEDS衍生密钥算法生成
     * KEYBLOCK：2字节BDK长度+BDK+6字节随机数
     */
    private byte[] out;

    /**
     * MAC数据包：用MACKEY对MAC数据进行的TEDS-CMAC/AES-CMAC
     * MAC数据：KeyHead数据包+KEYBLOCK
     */
    private byte[] mac;

    /**
     * TR-31包
     * RP/LANDI:
     * KeyHead数据包+OUT数据包(ASCII码表示)+MAC数据包(ASCII码表示)
     * FSDK(TR31):
     * DBH+KeyHead数据包+OUT数据包(ASCII码表示)+MAC数据包(ASCII码表示)
     */
    private byte[] tr31;

    /**
     * 密钥KCV
     */
    private byte[] kcv;


    public TR31() {

    }

    public TR31 setKey(byte[] key) {
        this.key = key;
        keyLength = Bytes.concat(new byte[]{(byte) ((key.length * 8) >> 8)}, new byte[]{(byte) ((key.length * 8) & 0xFF)});
        return this;
    }


    public TR31 setKeyUsage(String keyUsage) {
        this.keyUsage = Strings.encode(keyUsage);
        return this;
    }

    public TR31 setKeyAlgorithm(byte keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public TR31 setModeOfUse(byte modeOfUse) {
        this.modeOfUse = modeOfUse;
        return this;
    }

    public TR31 setVerNum(byte[] verNum) {
        this.verNum = verNum;
        return this;
    }

    public TR31 setExportability(byte exportability) {
        this.exportability = exportability;
        return this;
    }

    public TR31 setKsn(String ksn) {
        this.ksn = ksn;
        if (!Strings.isNullOrEmpty(ksn)) {
            if (ksn.length() == 20) {
                ksnLength = new byte[]{0x31, 0x38};
            } else if (ksn.length() == 24) {
                ksnLength = new byte[]{0x31, 0x43};
            } else {
                throw new IllegalArgumentException("KSN length error");
            }
        }
        return this;
    }

    public TR31 setKeyBlockVersion(byte keyBlockVersion) {
        this.keyBlockVersion = keyBlockVersion;
        return this;
    }

    public TR31 setKeyBlockRandom(byte[] keyBlockRandom) {
        this.keyBlockRandom = keyBlockRandom;
        return this;
    }

    public char getKeyBlockVersion() {
        return (char) keyBlockVersion;
    }

    public byte[] getKey() {
        return key;
    }

    public String getKeyUsage() {
        return Strings.decode(keyUsage);
    }

    public char getKeyAlgorithm() {
        return (char) keyAlgorithm;
    }

    public String getVerNum() {
        return Strings.decode(verNum);
    }

    public char getModeOfUse() {
        return (char) modeOfUse;
    }

    public char getExportability() {
        return (char) exportability;
    }

    public String getKsn() {
        return ksn;
    }

    public byte[] getKeyBlockRandom() {
        return keyBlockRandom;
    }

    public byte[] getTr31() {
        return tr31;
    }

    public byte[] getKcv() {
        return kcv;
    }

    public boolean isDukpt() {
        return !Strings.isNullOrEmpty(ksn);
    }


    /**
     * 组包TR31
     *
     * @param tk
     * @return
     */
    public byte[] pack(byte[] tk) {
        //检查TK
        if (Bytes.isNullOrEmpty(tk)) {
            throw new IllegalArgumentException("TK not set");
        }
        PrintfUtil.d("TK", Bytes.toHexString(tk));
        /**
         * 组包KeyHead
         */
        //TR31长度
        int tr31Len = 0;
        tr31Length = new byte[]{0x00, 0x00, 0x00, 0x00};
        keyHead = Bytes.concat(tr31Length);
        //KeyUsage
//        if (Bytes.isNullOrEmpty(keyUsage)) {
//            throw new IllegalArgumentException("KeyUsage not set");
//        }
        keyHead = Bytes.concat(keyHead, keyUsage);
        PrintfUtil.d("KeyUsage", Strings.decode(keyUsage));
        //keyAlgorithm
        if (keyAlgorithm == 0x00) {
            PrintfUtil.e("TR31", "KeyAlgorithm not set");
            throw new IllegalArgumentException("KeyAlgorithm not set");
        }
        keyHead = Bytes.concat(keyHead, new byte[]{keyAlgorithm});
        PrintfUtil.d("KeyAlgorithm", (char) keyAlgorithm + "");
        //ModeOfUse
//        if (modeOfUse == 0x00) {
//            throw new IllegalArgumentException("ModeOfUse not set");
//        }
        keyHead = Bytes.concat(keyHead, new byte[]{modeOfUse});
        PrintfUtil.d("ModeOfUse", (char) modeOfUse + "");
        if (!checkKeyUsageAndModeOfUse()) {
            throw new IllegalArgumentException("keyUsage and  ModeOfUse not match");
        }
        //VerNum
        if (verNum.length != 2) {
            PrintfUtil.e("TR31", "VerNum length error");
            throw new IllegalArgumentException("VerNum length error");
        }
        keyHead = Bytes.concat(keyHead, verNum);
        PrintfUtil.d("VerNum", Bytes.toHexString(verNum) + "");
        //Exportability
//        if (exportability == 0x00) {
//            throw new IllegalArgumentException("Exportability not set");
//        }
        keyHead = Bytes.concat(keyHead, new byte[]{exportability});
        PrintfUtil.d("Exportability", Bytes.toHexString(exportability));
        //是否有自定义域
        boolean option = false;
        optionalNum = new byte[]{0x30, 0x30};
        if (!Strings.isNullOrEmpty(ksn)) {
            option = true;
            optionalNum[1]++;
        }
        PrintfUtil.d("OptionalNum", Bytes.toHexString(optionalNum));
        //自定义域数量
        keyHead = Bytes.concat(keyHead, optionalNum);
        //预留域 0x30 0x30
        keyHead = Bytes.concat(keyHead, new byte[]{0x30, 0x30});
        //自定义域
        if (option) {
            //有KS
            if (!Strings.isNullOrEmpty(ksn)) {
                //KS
                keyHead = Bytes.concat(keyHead, new byte[]{0x4B, 0x53});
                keyHead = Bytes.concat(keyHead, ksnLength);
                if (!((keyAlgorithm == KeyAlgorithm.TDEA && ksn.length() == 20) || (keyAlgorithm == KeyAlgorithm.AES && ksn.length() == 24))) {
                    PrintfUtil.e("TR31", "KSN length not match KeyAlgorithm");
                    throw new IllegalArgumentException("KSN length not match KeyAlgorithm");
                }
                PrintfUtil.d("KSN", ksn);
                byte[] ksn_ascii = Strings.encode(ksn);
                keyHead = Bytes.concat(keyHead, ksn_ascii);
                PrintfUtil.d("KSN-ASCII", Bytes.toHexString(ksn_ascii));
            }
        }
        //暂不支持A、C KeyBlockVersion
        if (!(keyBlockVersion == KeyBlockVersion.B || keyBlockVersion == KeyBlockVersion.D)) {
            throw new IllegalArgumentException("Unknow KeyBlockVersion");
        }
        //KeyBolckVersion
        if (keyAlgorithm == KeyAlgorithm.TDEA) {
            keyBlockVersion = KeyBlockVersion.B;
        } else if (keyAlgorithm == KeyAlgorithm.AES) {
            keyBlockVersion = KeyBlockVersion.D;
        }

        keyHead = Bytes.concat(new byte[]{keyBlockVersion}, keyHead);
        PrintfUtil.d("KeyBlockVersion", Bytes.toHexString(keyBlockVersion));
        PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
        /**
         * 组包KeyBlock
         */
        //Key
        if (Bytes.isNullOrEmpty(key)) {
            PrintfUtil.e("TR31", "Key not set");
            throw new IllegalArgumentException("Key not set");
        }
        PrintfUtil.d("Key", Bytes.toHexString(key));
        PrintfUtil.d("KeyLen", key.length + "");
        //KCV
        if (keyAlgorithm == KeyAlgorithm.TDEA) {
            kcv = Bytes.subBytes(AlgUtil.tdesKCV(key), 0, 3);
        } else if (keyAlgorithm == KeyAlgorithm.AES) {
            kcv = Bytes.subBytes(AlgUtil.aesKCV(key), 0, 5);
        }
        if (!Bytes.isNullOrEmpty(kcv)) {
            PrintfUtil.d("KCV", Bytes.toHexString(kcv));
        }
        // KeyBlockRandom
        int paddingLen = 0;
        if (keyBlockVersion == KeyBlockVersion.B) {
            paddingLen = 8 - (2 + key.length) % 8;
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            paddingLen = 16 - (2 + key.length) % 16;
        }
        keyBlockRandom = AlgUtil.getRandom(paddingLen);
        PrintfUtil.d("PaddingLen", paddingLen + "");
        PrintfUtil.d("KeyBlockRandom", Bytes.toHexString(keyBlockRandom));
        keyBlock = Bytes.concat(keyLength, key, keyBlockRandom);
        PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
        /**
         * 组包MAC
         */
        int outLen = 2 + key.length + paddingLen;
        PrintfUtil.d("OutLen", outLen + "");
        byte[] macKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            //MacKey
            macKey = desDeriveMacKey(tk);
            PrintfUtil.d("MacKey", Bytes.toHexString(macKey));
            tr31Len = keyHead.length + outLen * 2 + TR31_TEDS_MAC_LEN;
            keyHead[1] = tr31Length[0] = (byte) (tr31Len / 1000 + '0');
            keyHead[2] = tr31Length[1] = (byte) ((tr31Len % 1000) / 100 + '0');
            keyHead[3] = tr31Length[2] = (byte) ((tr31Len % 100) / 10 + '0');
            keyHead[4] = tr31Length[3] = (byte) ((tr31Len % 10) + '0');
            PrintfUtil.d("Tr31Len", tr31Len + "");
            PrintfUtil.d("Tr31Length-ASCII", Bytes.toHexString(tr31Length));
            PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
            //Mac
            mac = AlgUtil.tdesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
            PrintfUtil.d("Mac", Bytes.toHexString(mac));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            //MacKey
            macKey = aesDeriveMacKey(tk);
            PrintfUtil.d("MacKey", Bytes.toHexString(macKey));
            tr31Len = keyHead.length + outLen * 2 + TR31_AES_MAC_LEN;
            keyHead[1] = tr31Length[0] = (byte) (tr31Len / 1000 + '0');
            keyHead[2] = tr31Length[1] = (byte) ((tr31Len % 1000) / 100 + '0');
            keyHead[3] = tr31Length[2] = (byte) ((tr31Len % 100) / 10 + '0');
            keyHead[4] = tr31Length[3] = (byte) ((tr31Len % 10) + '0');
            PrintfUtil.d("Tr31Len", tr31Len + "");
            PrintfUtil.d("Tr31Len-ASCII", Bytes.toHexString(tr31Length));
            PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
            //Mac
            mac = AlgUtil.aesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
            PrintfUtil.d("Mac", Bytes.toHexString(mac));
        }
        //释放
        if (!Bytes.isNullOrEmpty(macKey)) {
            Arrays.fill(macKey, (byte) 0x00);
        }
        /**
         * 组包Out
         */
        byte[] encKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            //EncKey
            encKey = desDeriveEncKey(tk);
            PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
            //Out
            out = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.AlgorithmModel.CBC, AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, keyBlock);
            PrintfUtil.d("Out", Bytes.toHexString(out));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            //EncKey
            encKey = aesDeriveEncKey(tk);
            PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
            //Out
            out = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.AES, AlgUtil.AlgorithmModel.CBC, AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, keyBlock);
            PrintfUtil.d("OutLen", out.length + "");
            out = Bytes.subBytes(out, 0, outLen);
            PrintfUtil.d("Out", Bytes.toHexString(out));
        }
        //释放
        if (!Bytes.isNullOrEmpty(encKey)) {
            Arrays.fill(encKey, (byte) 0x00);
        }
        //转ASCII
        byte[] out_ascii = Strings.encode(Bytes.toHexString(out));
        PrintfUtil.d("Out-ASCII", Bytes.toHexString(out_ascii));
        byte[] mac_ascii = Strings.encode(Bytes.toHexString(mac));
        PrintfUtil.d("Mac-ASCII", Bytes.toHexString(mac_ascii));
        tr31 = Bytes.concat(keyHead, out_ascii, mac_ascii);
        PrintfUtil.d("TR-31", Bytes.toHexString(tr31));
        return tr31;
    }

    /**
     * @param tr31
     * @param tk
     */
    public void unpack(byte[] tr31, byte[] tk) {
        this.tr31 = tr31;
        PrintfUtil.d("TR-31", Bytes.toHexString(tr31));
        //检查TK
        if (Bytes.isNullOrEmpty(tk)) {
            PrintfUtil.e("TR31", "TK not set");
            throw new IllegalArgumentException("TK not set");
        }
        PrintfUtil.d("TK", Bytes.toHexString(tk));
        int index = 0;
        //KeyBlockVersion
        this.keyBlockVersion = tr31[index++];
        PrintfUtil.d("KeyBlockVersion", Bytes.toHexString(keyBlockVersion));
        if (!(keyBlockVersion == KeyBlockVersion.B || keyBlockVersion == KeyBlockVersion.D)) {
            PrintfUtil.e("TR31", "Unknow KeyBlockVersion");
            throw new IllegalArgumentException("Unknow KeyBlockVersion");
        }
        //Tr31Len
        this.tr31Length = Bytes.subBytes(tr31, index, 4);
        PrintfUtil.d("Tr31Length-ASCII", Bytes.toHexString(tr31Length));
        index += 4;
        int tr31Len = Integer.valueOf(Strings.decode(tr31Length));
        PrintfUtil.d("Tr31Len", tr31Len + "");
        if (tr31Len != tr31.length) {
            PrintfUtil.e("TR31", "Tr31 length error");
            throw new IllegalArgumentException("Tr31 length error");
        }
        //KeyUsage
        keyUsage = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("KeyUsage", Strings.decode(keyUsage));
        //keyAlgorithm
        keyAlgorithm = tr31[index++];
        PrintfUtil.d("KeyAlgorithm", (char) keyAlgorithm + "");
        //modeOfUse
        modeOfUse = tr31[index++];
        PrintfUtil.d("ModeOfUse", (char) modeOfUse + "");
        //verNum
        verNum = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("VerNum", Bytes.toHexString(verNum));
        //Exportability
        exportability = tr31[index++];
        PrintfUtil.d("Exportability", (char) exportability + "");
        //自定义域数量
        optionalNum = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("OptionalNum", Bytes.toHexString(optionalNum));
        //预留域 0x30 0x30
        index += 2;
        //Mac长度
        int macLen = 0;
        //有域
        int optionalSzie = Integer.valueOf(Strings.decode(optionalNum));
        if (optionalSzie > 0) {
            for (int i = 0; i < optionalSzie; i++) {
                byte[] tag = new byte[]{tr31[index++], tr31[index++]};
                //解析KS
                if (Bytes.equals(tag, new byte[]{0X4B, 0X53})) {
                    //KSN
                    int ksnLen = 0;
                    ksnLen = Integer.parseInt(Strings.decode(new byte[]{tr31[index++], tr31[index++]}), 16);
                    //减去2字节TAG+2字节长度
                    ksnLen = ksnLen - 4;
                    if (!(ksnLen == 20 || ksnLen == 24)) {
                        PrintfUtil.e("TR31", "Ksn length error");
                        throw new IllegalArgumentException("Ksn length error");
                    }
                    if (!((keyAlgorithm == KeyAlgorithm.TDEA && ksnLen == 20) ||
                            (keyAlgorithm == KeyAlgorithm.AES && ksnLen == 24))) {
                        PrintfUtil.e("TR31", "KSN length not match KeyAlgorithm");
                        throw new IllegalArgumentException("KSN length not match KeyAlgorithm");
                    }
                    ksn = Strings.decode(Bytes.subBytes(tr31, index, ksnLen));
                    index += ksnLen;
                    PrintfUtil.d("KsnLen", ksnLen + "");
                    PrintfUtil.d("Ksn", ksn + "");
                }
            }
        }
        //KeyHead
        keyHead = Bytes.subBytes(tr31, 0, index);
        PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
        if (keyBlockVersion == KeyBlockVersion.B) {
            macLen = TR31_TEDS_MAC_LEN;
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            macLen = TR31_AES_MAC_LEN;
        }
        //Out
        byte[] out_ascii = Bytes.subBytes(tr31, index, tr31.length - index - macLen);
        PrintfUtil.d("Out-ASCII", Bytes.toHexString(out_ascii));
        out = Bytes.fromHexString(Strings.decode(out_ascii));
        PrintfUtil.d("Out", Bytes.toHexString(out));
        //Mac
        byte[] mac_ascii = Bytes.subBytes(tr31, tr31.length - macLen, macLen);
        PrintfUtil.d("Mac-ASCII", Bytes.toHexString(mac_ascii));
        mac = Bytes.fromHexString(Strings.decode(mac_ascii));
        PrintfUtil.d("Mac", Bytes.toHexString(mac));
        //KeyBolck
        byte[] encKey;
        if (keyBlockVersion == KeyBlockVersion.B) {
            //EncKey
            encKey = desDeriveEncKey(tk);
            PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
            //Out
            keyBlock = AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.AlgorithmModel.CBC, AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, out);
            PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            //EncKey
            encKey = aesDeriveEncKey(tk);
            PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
            //KeyBlock
            keyBlock = AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.AES, AlgUtil.AlgorithmModel.CBC, AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, out);
            PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
            //释放
            Arrays.fill(encKey, (byte) 0x00);
        }
        //Key
        keyLength = new byte[]{keyBlock[0], keyBlock[1]};
        int keyLen = Bytes.toInt(keyLength) / 8;
        PrintfUtil.d("KeyLen", keyLen + "");
        key = Bytes.subBytes(keyBlock, 2, keyLen);
        PrintfUtil.d("Key", Bytes.toHexString(key));
        // KeyBlockRandom
        int paddingLen = 0;
        if (keyBlockRandom == null) {
            if (keyBlockVersion == KeyBlockVersion.B) {
                paddingLen = 8 - (2 + key.length) % 8;
            } else if (keyBlockVersion == KeyBlockVersion.D) {
                paddingLen = 16 - (2 + key.length) % 16;
            }
        } else {
            paddingLen = keyBlockRandom.length;
        }
        PrintfUtil.d("PaddingLen", paddingLen + "");
        keyBlockRandom = Bytes.subBytes(keyBlock, 2 + keyLen, paddingLen);
        PrintfUtil.d("KeyBlockRandom", Bytes.toHexString(keyBlockRandom));
        keyBlock = Bytes.subBytes(keyBlock, 0, 2 + keyLen + paddingLen);
        PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
        //KCV
        if (keyAlgorithm == KeyAlgorithm.TDEA) {
            kcv = Bytes.subBytes(AlgUtil.tdesKCV(key), 0, 3);
        } else if (keyAlgorithm == KeyAlgorithm.AES) {
            kcv = Bytes.subBytes(AlgUtil.aesKCV(key), 0, 5);
        }
        if (!Bytes.isNullOrEmpty(kcv)) {
            PrintfUtil.d("KCV", Bytes.toHexString(kcv));
        }
        byte[] checkMac = null;
        //校验MAC
        byte[] macKey;
        if (keyBlockVersion == KeyBlockVersion.B) {
            //MacKey
            macKey = desDeriveMacKey(tk);
            PrintfUtil.d("MacKey", Bytes.toHexString(macKey));
            checkMac = AlgUtil.tdesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
            PrintfUtil.d("CheckMac", Bytes.toHexString(checkMac));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            //MacKey
            macKey = aesDeriveMacKey(tk);
            PrintfUtil.d("MacKey", Bytes.toHexString(macKey));
            //Mac
            checkMac = AlgUtil.aesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
            PrintfUtil.d("CheckMac", Bytes.toHexString(checkMac));
            //释放
            Arrays.fill(macKey, (byte) 0x00);
        }
        if (!Bytes.equals(checkMac, mac)) {
            PrintfUtil.e("TR31", "Check Mac error");
            throw new IllegalArgumentException("Check Mac error");
        }
    }


    /**
     * @param tr31
     */
    public void unpackKeyHead(byte[] tr31) {
        this.tr31 = tr31;
        PrintfUtil.d("TR-31", Bytes.toHexString(tr31));
        int index = 0;
        //KeyBlockVersion
        this.keyBlockVersion = tr31[index++];
        PrintfUtil.d("KeyBlockVersion", Bytes.toHexString(keyBlockVersion));
        if (!(keyBlockVersion == KeyBlockVersion.B || keyBlockVersion == KeyBlockVersion.D)) {
            PrintfUtil.e("TR31", "Unknow KeyBlockVersion");
            throw new IllegalArgumentException("Unknow KeyBlockVersion");
        }
        //Tr31Len
        this.tr31Length = Bytes.subBytes(tr31, index, 4);
        PrintfUtil.d("Tr31Length-ASCII", Bytes.toHexString(tr31Length));
        index += 4;
        int tr31Len = Integer.valueOf(Strings.decode(tr31Length));
        PrintfUtil.d("Tr31Len", tr31Len + "");
        if (tr31Len != tr31.length) {
            PrintfUtil.e("TR31", "Tr31 length error");
            throw new IllegalArgumentException("Tr31 length error");
        }
        //KeyUsage
        keyUsage = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("KeyUsage", Strings.decode(keyUsage));
        //keyAlgorithm
        keyAlgorithm = tr31[index++];
        PrintfUtil.d("KeyAlgorithm", (char) keyAlgorithm + "");
        //modeOfUse
        modeOfUse = tr31[index++];
        PrintfUtil.d("ModeOfUse", (char) modeOfUse + "");
        //verNum
        verNum = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("VerNum", Bytes.toHexString(verNum));
        //Exportability
        exportability = tr31[index++];
        PrintfUtil.d("Exportability", (char) exportability + "");
        //自定义域数量
        optionalNum = new byte[]{tr31[index++], tr31[index++]};
        PrintfUtil.d("OptionalNum", Bytes.toHexString(optionalNum));
        //预留域 0x30 0x30
        index += 2;
        //Mac长度
        int macLen = 0;
        //有域
        int optionalSzie = Integer.valueOf(Strings.decode(optionalNum));
        if (optionalSzie > 0) {
            for (int i = 0; i < optionalSzie; i++) {
                byte[] tag = new byte[]{tr31[index++], tr31[index++]};
                //解析KS
                if (Bytes.equals(tag, new byte[]{0X4B, 0X53})) {
                    //KSN
                    int ksnLen = 0;
                    ksnLen = Integer.parseInt(Strings.decode(new byte[]{tr31[index++], tr31[index++]}), 16);
                    //减去2字节TAG+2字节长度
                    ksnLen = ksnLen - 4;
                    if (!(ksnLen == 20 || ksnLen == 24)) {
                        PrintfUtil.e("TR31", "Ksn length error");
                        throw new IllegalArgumentException("Ksn length error");
                    }
                    if (!((keyAlgorithm == KeyAlgorithm.TDEA && ksnLen == 20) ||
                            (keyAlgorithm == KeyAlgorithm.AES && ksnLen == 24))) {
                        PrintfUtil.e("TR31", "KSN length not match KeyAlgorithm");
                        throw new IllegalArgumentException("KSN length not match KeyAlgorithm");
                    }
                    ksn = Strings.decode(Bytes.subBytes(tr31, index, ksnLen));
                    index += ksnLen;
                    PrintfUtil.d("KsnLen", ksnLen + "");
                    PrintfUtil.d("Ksn", ksn);
                }
            }
        }
        //KeyHead
        keyHead = Bytes.subBytes(tr31, 0, index);
        PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
    }

    /**
     * Des衍生MackKey
     *
     * @param kbpk
     * @return
     */
    public static byte[] desDeriveMacKey(byte[] kbpk) {
        byte[] macKey;
        if (kbpk.length == 16) {
            byte[] iv1 = Bytes.fromHexString("0100010000000080");
            macKey = AlgUtil.tdesCMAC(kbpk, iv1);
            byte[] iv2 = Bytes.fromHexString("0200010000000080");
            macKey = Bytes.concat(macKey, AlgUtil.tdesCMAC(kbpk, iv2));
            return macKey;
        } else if (kbpk.length == 24) {
            byte[] iv1 = Bytes.fromHexString("01000100000100C0");
            macKey = AlgUtil.tdesCMAC(kbpk, iv1);
            byte[] iv2 = Bytes.fromHexString("02000100000100C0");
            macKey = Bytes.concat(macKey, AlgUtil.tdesCMAC(kbpk, iv2));
            byte[] iv3 = Bytes.fromHexString("03000100000100C0");
            macKey = Bytes.concat(macKey, AlgUtil.tdesCMAC(kbpk, iv3));
            return macKey;
        } else {
            PrintfUtil.e("TR31", "KBPK length error");
            throw new IllegalArgumentException("KBPK length error");
        }
    }

    /**
     * Des衍生EncKey
     *
     * @param kbpk
     * @return
     */
    public static byte[] desDeriveEncKey(byte[] kbpk) {
        byte[] encKey;
        if (kbpk.length == 16) {
            byte[] iv1 = Bytes.fromHexString("0100000000000080");
            encKey = AlgUtil.tdesCMAC(kbpk, iv1);
            byte[] iv2 = Bytes.fromHexString("0200000000000080");
            encKey = Bytes.concat(encKey, AlgUtil.tdesCMAC(kbpk, iv2));
            return encKey;
        } else if (kbpk.length == 24) {
            byte[] iv1 = Bytes.fromHexString("01000000000100C0");
            encKey = AlgUtil.tdesCMAC(kbpk, iv1);
            byte[] iv2 = Bytes.fromHexString("02000000000100C0");
            encKey = Bytes.concat(encKey, AlgUtil.tdesCMAC(kbpk, iv2));
            byte[] iv3 = Bytes.fromHexString("03000000000100C0");
            encKey = Bytes.concat(encKey, AlgUtil.tdesCMAC(kbpk, iv3));
            return encKey;
        } else {
            PrintfUtil.e("TR31", "KBPK length error");
            throw new IllegalArgumentException("KBPK length error");
        }
    }

    /**
     * TR31 AES衍生MacKey
     *
     * @param kpbk
     * @return
     */
    private static byte[] aesDeriveMacKey(byte[] kpbk) {
        byte[] macKey;
        if (kpbk.length == 16) {
            macKey = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0100010000020080"));
        } else if (kpbk.length == 24) {
            byte[] macKey1 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("01000100000300C0"));
            byte[] macKey2 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("02000100000300C0"));
            macKey = Bytes.concat(macKey1, Bytes.subBytes(macKey2, 0, 8));
        } else if (kpbk.length == 32) {
            byte[] macKey1 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0100010000040100"));
            byte[] macKey2 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0200010000040100"));
            macKey = Bytes.concat(macKey1, macKey2);
        } else {
            PrintfUtil.e("TR31", "KBPK length error");
            throw new IllegalArgumentException("KBPK length error");
        }
        return macKey;
    }

    /**
     * TR31 AES衍生EncKey
     *
     * @param kpbk
     * @return
     */
    private static byte[] aesDeriveEncKey(byte[] kpbk) {
        byte[] encKey;
        if (kpbk.length == 16) {
            encKey = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0100000000020080"));
        } else if (kpbk.length == 24) {
            byte[] encKey1 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("01000000000300C0"));
            byte[] encKey2 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("02000000000300C0"));
            encKey = Bytes.concat(encKey1, Bytes.subBytes(encKey2, 0, 8));
        } else if (kpbk.length == 32) {
            byte[] encKey1 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0100000000040100"));
            byte[] encKey2 = AlgUtil.aesCMAC(kpbk, Bytes.fromHexString("0200000000040100"));
            encKey = Bytes.concat(encKey1, encKey2);
        } else {
            PrintfUtil.e("TR31", "KBPK length error");
            throw new IllegalArgumentException("KBPK length error");
        }
        return encKey;
    }

    /**
     * 校验密钥用途以及模式
     * @return
     */
    private boolean checkKeyUsageAndModeOfUse() {
        Map<String, String[]> map = new HashMap<>();
        map.put("01",new String[]{ModeOfUse.ENC_OR_WRAP_ONLY+""});
        map.put(KeyUsage.BDK, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DUKPT_INIT_KEY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.BASE_KEY_VARIANT_KEY, new String[]{ModeOfUse.CREATE_KEY_VARIANTS + ""});
        map.put(KeyUsage.CVK, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.SYMMETRIC_KEY_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.DECIMALIZATION_TABLE_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.APPLICATION_CRYPTOGRAMS, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.MESSAGING_FOR_CONFIDENTIALITY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.MESSAGING_FOR_INTEGRITY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DATA_AUTHENTICATION_CODE, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DYNAMIC_NUMBERS, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.CARD_PERSONALIZATION, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.OTHER, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.IV, new String[]{ModeOfUse.NO_RESTRICTIONS + ""});
        map.put(KeyUsage.KEY_ENC_OR_WRAP, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.TR31_PROTECTION_KEY, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.TR34_ASYMMETRIC_KEY, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_AGREE_WRAP, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + "",
                ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.ISO_16609_MAC_ALGORITHM_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_2, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_3, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_4, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_1999_MAC_ALGORITHM_5, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.CMAC, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.HMAC, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_2011_MAC_ALGORITHM_6, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.PIN_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_SIGNATURE, new String[]{ModeOfUse.SIGNATURE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.LOG_SIGNATURE, new String[]{ModeOfUse.SIGNATURE_ONLY + ""});
        map.put(KeyUsage.CA, new String[]{ModeOfUse.SIGNATURE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.NONX9_24, new String[]{ModeOfUse.SIGNATURE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + "",
                ModeOfUse.SIGN_AND_DEC + "",
                ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.KPV, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.IBM_3624, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.VISA_PVV, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.X9_132_ALGORITHM_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.X9_132_ALGORITHM_2, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        if (map.get(Strings.decode(keyUsage)) == null) {
            throw new IllegalArgumentException("KeyUsage error");
        } else {
            String[] values = map.get(Strings.decode(keyUsage));
            List<String> modeOfUses = Arrays.asList(values);
            return modeOfUses.contains((char) modeOfUse + "");
        }
    }
}
