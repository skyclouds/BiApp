package com.biapp.key;

import com.biapp.util.AlgUtil;
import com.biapp.util.FormatUtil;
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
     * TR31- Version B MAC域长度
     */
    public final static int KEY_BLOCK_VERSION_B_MAC_LENGTH = 16;

    /**
     * TR31- Version D MAC域长度
     */
    public final static int KEY_BLOCK_VERSION_D_MAC_LENGTH = 32;

    /**
     * KeyHead数据包：KeyBlockVersion（1A）+TR-31包长度（4N）+KeyUsage（2AN）+KeyAlgorithm（1A）+ModeOfUse（1A）+VerNum（2AN）+Exportability（1A）+Optional
     * Block Num（2N）+Reserved （2AN）+ Optional Block [n]
     */
    private byte[] keyHead;

    /**
     * @see KeyBlockVersion KeyBlockVersion
     */
    private byte keyBlockVersion = KeyBlockVersion.B;

    /**
     * TR-31包长度(4N)
     */
    private int tr31Length = 0;

    /**
     * 密钥用途（2AN）
     *
     * @see KeyUsage
     */
    private String keyUsage;

    /**
     * 密钥算法（1A）
     *
     * @see KeyAlgorithm
     */
    private byte keyAlgorithm;

    /**
     * 使用模式（1A）
     *
     * @see ModeOfUse
     */
    private byte modeOfUse;

    /**
     * 密钥版本（2AN）
     *
     * @see VerNum
     */
    private String verNum = VerNum.NONE;

    /**
     * 导出能力（1A）
     *
     * @see Exportability
     */
    private byte exportability = 0x30;

    /**
     * Optional域
     *
     * @see OptionalBlockID
     */
    private Map<String, OptionalBlock> optionalBlocks = new HashMap<>();

    /**
     * 预留域（2AN，目前一固定为00）
     */
    private String reserved = "00";

    /**
     * 2字节密钥明文Bit长度+key+算法随机数填充
     */
    private byte[] keyBlock;

    /**
     * 密钥明文
     */
    private byte[] key;

    /**
     * 算法随机数填充
     */
    private byte[] keyBlockRandom;

    /**
     * OUT数据包：用ENCKEY对KEYBLOCK进行TEDS/AES CBC加密初始向量为MAC
     */
    private byte[] out;

    /**
     * MAC数据包：用MACKEY对MAC数据进行的TEDS-CMAC/AES-CMAC MAC数据：KeyHead+KEYBLOCK
     */
    private byte[] mac;

    /**
     * TR-31包
     */
    private byte[] tr31;

    public TR31() {

    }

    public byte[] getKeyHead() {
        return keyHead;
    }

    public byte getKeyBlockVersion() {
        return keyBlockVersion;
    }

    public TR31 setKeyBlockVersion(byte keyBlockVersion) {
        this.keyBlockVersion = keyBlockVersion;
        return this;
    }

    public int getTr31Length() {
        return tr31Length;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public TR31 setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }

    public byte getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public TR31 setKeyAlgorithm(byte keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public byte getModeOfUse() {
        return modeOfUse;
    }

    public TR31 setModeOfUse(byte modeOfUse) {
        this.modeOfUse = modeOfUse;
        return this;
    }

    public String getVerNum() {
        return verNum;
    }

    public TR31 setVerNum(String verNum) {
        this.verNum = verNum;
        return this;
    }

    public byte getExportability() {
        return exportability;
    }

    public TR31 setExportability(byte exportability) {
        this.exportability = exportability;
        return this;
    }

    public Map<String, OptionalBlock> getOptionalBlocks() {
        return optionalBlocks;
    }

    public TR31 addOptionalBlock(String optionalBlockID, OptionalBlock optionalBlock) {
        optionalBlocks.put(optionalBlockID, optionalBlock);
        return this;
    }

    public String getReserved() {
        return reserved;
    }

    public byte[] getKeyBlock() {
        return keyBlock;
    }

    public byte[] getKey() {
        return key;
    }

    public TR31 setKey(byte[] key) {
        this.key = key;
        return this;
    }

    public byte[] getKeyBlockRandom() {
        return keyBlockRandom;
    }

    public byte[] getOut() {
        return out;
    }

    public byte[] getMac() {
        return mac;
    }

    public byte[] getTr31() {
        return tr31;
    }

    /**
     * 组包TR31
     *
     * @param bpk
     * @return
     */
    public byte[] pack(byte[] bpk) {
        // 检查BPK
        if (Bytes.isNullOrEmpty(bpk)) {
            throw new IllegalArgumentException("BPK not set");
        }
        PrintfUtil.d("BPK", Bytes.toHexString(bpk));
        // Key
        if (Bytes.isNullOrEmpty(key)) {
            throw new IllegalArgumentException("Key not set");
        }
        PrintfUtil.d("Key", Bytes.toHexString(key));
        // 设置KP
        if (keyBlockVersion == KeyBlockVersion.B) {
            optionalBlocks.put(OptionalBlockID.KP,
                    new OptionalBlock(KCVAlgorithm.LEGACY + Bytes.toHexString(Bytes.subBytes(AlgUtil.tdesLegacyKCV(bpk), 0, 3))));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            optionalBlocks.put(OptionalBlockID.KP,
                    new OptionalBlock(KCVAlgorithm.CMAC + Bytes.toHexString(Bytes.subBytes(AlgUtil.aesCMACKCV(bpk), 0, 5))));
        }
        // 设置KeyHead
        setKeyHead();
        // 设置KeyBlock
        setKeyBlock();
        // 计算MAC
        caclMAC(bpk);
        // 计算OUT
        caclOUT(bpk);
        // 释放
        Arrays.fill(bpk, (byte) 0x00);
        // 转ASCII
        byte[] out_ascii = Strings.encode(Bytes.toHexString(out));
        PrintfUtil.d("Out-ASCII", Bytes.toHexString(out_ascii));
        byte[] mac_ascii = Strings.encode(Bytes.toHexString(mac));
        PrintfUtil.d("Mac-ASCII", Bytes.toHexString(mac_ascii));
        tr31 = Bytes.concat(keyHead, out_ascii, mac_ascii);
        PrintfUtil.d("TR-31", new String(tr31));
        return tr31;
    }

    /**
     * 设置KeyHead
     */
    private void setKeyHead() {
        // 暂不支持A、C KeyBlockVersion
        if (!(keyBlockVersion == KeyBlockVersion.B || keyBlockVersion == KeyBlockVersion.D)) {
            throw new IllegalArgumentException("Only Support KeyBlockVersion B/D");
        }
        keyHead = new byte[]{keyBlockVersion};
        PrintfUtil.d("KeyBlockVersion", (char) keyBlockVersion + "");
        // TR31包长度
        byte[] tr31LenData = FormatUtil.addHead('0', 4, tr31Length + "").getBytes();
        keyHead = Bytes.concat(keyHead, tr31LenData);
        // KeyUsage
        if (Strings.isNullOrEmpty(keyUsage)) {
            throw new IllegalArgumentException("KeyUsage not set");
        }
        if (keyUsage.length() != 2) {
            throw new IllegalArgumentException("KeyUsage length error");
        }
        keyHead = Bytes.concat(keyHead, keyUsage.getBytes());
        PrintfUtil.d("KeyUsage", keyUsage);
        // keyAlgorithm
        if (keyAlgorithm == 0x00) {
            throw new IllegalArgumentException("KeyAlgorithm not set");
        }
        keyHead = Bytes.concat(keyHead, new byte[]{keyAlgorithm});
        PrintfUtil.d("KeyAlgorithm", (char) keyAlgorithm + "");
        // 设置KC域
        if (keyAlgorithm == KeyAlgorithm.TDEA) {
            optionalBlocks.put(OptionalBlockID.KC,
                    new OptionalBlock(KCVAlgorithm.LEGACY + Bytes.toHexString(Bytes.subBytes(AlgUtil.tdesLegacyKCV(key), 0, 3))));
        } else if (keyAlgorithm == KeyAlgorithm.AES) {
            optionalBlocks.put(OptionalBlockID.KC,
                    new OptionalBlock(KCVAlgorithm.CMAC + Bytes.toHexString(Bytes.subBytes(AlgUtil.tdesLegacyKCV(key), 0, 3))));
        }
        // ModeOfUse
        if (modeOfUse == 0x00) {
            throw new IllegalArgumentException("ModeOfUse not set");
        }
        keyHead = Bytes.concat(keyHead, new byte[]{modeOfUse});
        PrintfUtil.d("ModeOfUse", (char) modeOfUse + "");
        if (!checkKeyUsageAndModeOfUse()) {
            throw new IllegalArgumentException("keyUsage and  ModeOfUse not match");
        }
        // VerNum
        if (Strings.isNullOrEmpty(verNum)) {
            throw new IllegalArgumentException("VerNum not set");
        }
        if (verNum.length() != 2) {
            throw new IllegalArgumentException("VerNum length error");
        }
        keyHead = Bytes.concat(keyHead, verNum.getBytes());
        PrintfUtil.d("VerNum", verNum + "");
        // Exportability
        if (exportability == 0x00) {
            throw new IllegalArgumentException("Exportability not set");
        }
        keyHead = Bytes.concat(keyHead, new byte[]{exportability});
        PrintfUtil.d("Exportability", (char) exportability + "");
        // 可选域数量
        if (optionalBlocks.size() > Short.MAX_VALUE) {
            throw new IllegalArgumentException("OptionalBlock Num over limit");
        }
        short optionalNum = (short) optionalBlocks.size();
        PrintfUtil.d("OptionalNum", optionalNum + "");
        keyHead = Bytes.concat(keyHead, FormatUtil.addHead('0', 2, optionalNum + "").getBytes());
        // 预留域
        PrintfUtil.d("Reserved", reserved);
        keyHead = Bytes.concat(keyHead, reserved.getBytes());
        // 可选域
        for (Map.Entry<String, OptionalBlock> entry : optionalBlocks.entrySet()) {
            if (entry.getKey().equals(OptionalBlockID.KS)) {
                if (!((keyAlgorithm == KeyAlgorithm.TDEA && entry.getValue().getData().length() == 20)
                        || (keyAlgorithm == KeyAlgorithm.AES && entry.getValue().getData().length() == 24))) {
                    throw new IllegalArgumentException("KSN length not match KeyAlgorithm");
                } else {
                    PrintfUtil.d("KSN", entry.getValue().getData());
                    keyHead = Bytes.concat(keyHead, entry.getKey().getBytes(), entry.getValue().getLength().getBytes(),
                            entry.getValue().getData().getBytes());
                }
            } else if (entry.getKey().equals(OptionalBlockID.KP)) {
                PrintfUtil.d("KBPK KCV", entry.getValue().getData().substring(2));
                keyHead = Bytes.concat(keyHead, entry.getKey().getBytes(), entry.getValue().getLength().getBytes(),
                        entry.getValue().getData().getBytes());
            } else if (entry.getKey().equals(OptionalBlockID.KC)) {
                PrintfUtil.d("KCV", entry.getValue().getData().substring(2));
                keyHead = Bytes.concat(keyHead, entry.getKey().getBytes(), entry.getValue().getLength().getBytes(),
                        entry.getValue().getData().getBytes());
            } else {
                throw new IllegalArgumentException("UnSupport OptionalBlockID " + entry.getKey());
            }
        }
        PrintfUtil.d("KeyHead", new String(keyHead));
    }

    /**
     * 设置KeyBlock
     */
    private void setKeyBlock() {
        if (key.length / 8 > Short.MAX_VALUE) {
            throw new IllegalArgumentException("Key size over limit");
        }
        short keyLen = (short) (key.length * 8);
        // KeyBlockRandom
        int paddingLen = 0;
        if (keyBlockVersion == KeyBlockVersion.B) {
            paddingLen = 8 - (2 + key.length) % 8;
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            paddingLen = 16 - (2 + key.length) % 16;
        }
        keyBlockRandom = AlgUtil.getRandom(paddingLen);
        PrintfUtil.d("KeyBlockRandom", Bytes.toHexString(keyBlockRandom));
        keyBlock = Bytes.concat(Bytes.fromInt(keyLen, 2), key, keyBlockRandom);
        PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
    }

    /**
     * 计算MAC
     *
     * @param bpk
     */
    private void caclMAC(byte[] bpk) {
        byte[] macKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            macKey = desDeriveMacKey(bpk);
            tr31Length = keyHead.length + keyBlock.length * 2 + KEY_BLOCK_VERSION_B_MAC_LENGTH;
            byte[] tr31LenData = FormatUtil.addHead('0', 4, tr31Length + "").getBytes();
            keyHead[1] = tr31LenData[0];
            keyHead[2] = tr31LenData[1];
            keyHead[3] = tr31LenData[2];
            keyHead[4] = tr31LenData[3];
            mac = AlgUtil.tdesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            macKey = aesDeriveMacKey(bpk);
            tr31Length = keyHead.length + keyBlock.length * 2 + KEY_BLOCK_VERSION_D_MAC_LENGTH;
            byte[] tr31LenData = FormatUtil.addHead('0', 4, tr31Length + "").getBytes();
            keyHead[1] = tr31LenData[0];
            keyHead[2] = tr31LenData[1];
            keyHead[3] = tr31LenData[2];
            keyHead[4] = tr31LenData[3];
            mac = AlgUtil.aesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
        }
        PrintfUtil.d("KeyHead", new String(keyHead));
        PrintfUtil.d("Mac", Bytes.toHexString(mac));
        // 释放
        Arrays.fill(macKey, (byte) 0x00);
    }

    /**
     * 计算OUT
     *
     * @param bpk
     */
    private void caclOUT(byte[] bpk) {
        byte[] encKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            encKey = desDeriveEncKey(bpk);
            out = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.AlgorithmModel.CBC,
                    AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, keyBlock);
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            encKey = aesDeriveEncKey(bpk);
            out = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.AES, AlgUtil.AlgorithmModel.CBC,
                    AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, keyBlock);
        }
        PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
        PrintfUtil.d("Out", Bytes.toHexString(out));
        // 释放
        Arrays.fill(encKey, (byte) 0x00);
    }

    /**
     * @param tr31
     * @param bpk
     */
    public void unpack(byte[] tr31, byte[] bpk) {
        this.tr31 = tr31;
        PrintfUtil.d("TR-31", new String(tr31));
        // 检查TK
        if (Bytes.isNullOrEmpty(bpk)) {
            PrintfUtil.e("TR31", "BPK not set");
            throw new IllegalArgumentException("BPK not set");
        }
        PrintfUtil.d("BPK", Bytes.toHexString(bpk));
        int index = 0;
        // KeyBlockVersion
        this.keyBlockVersion = tr31[index++];
        PrintfUtil.d("KeyBlockVersion", (char) keyBlockVersion + "");
        if (!(keyBlockVersion == KeyBlockVersion.B || keyBlockVersion == KeyBlockVersion.D)) {
            throw new IllegalArgumentException("Only Support KeyBlockVersion B/D");
        }
        // Tr31Len
        this.tr31Length = Integer.parseInt(Strings.decode(Bytes.subBytes(tr31, index, 4)));
        PrintfUtil.d("Tr31Length", tr31Length + "");
        index += 4;
        if (tr31Length != tr31.length) {
            throw new IllegalArgumentException("Tr31 length error");
        }
        // KeyUsage
        keyUsage = Strings.decode(new byte[]{tr31[index++], tr31[index++]});
        PrintfUtil.d("KeyUsage", keyUsage);
        // keyAlgorithm
        keyAlgorithm = tr31[index++];
        PrintfUtil.d("KeyAlgorithm", (char) keyAlgorithm + "");
        // modeOfUse
        modeOfUse = tr31[index++];
        PrintfUtil.d("ModeOfUse", (char) modeOfUse + "");
        // verNum
        verNum = Strings.decode(new byte[]{tr31[index++], tr31[index++]});
        PrintfUtil.d("VerNum", verNum);
        // Exportability
        exportability = tr31[index++];
        PrintfUtil.d("Exportability", (char) exportability + "");
        // 自定义域数量
        int optionalNum = Integer.parseInt(Strings.decode(new byte[]{tr31[index++], tr31[index++]}));
        PrintfUtil.d("OptionalNum", optionalNum + "");
        // 预留域 0x30 0x30
        reserved = Strings.decode(new byte[]{tr31[index++], tr31[index++]});
        PrintfUtil.d("Reserved", reserved);
        for (int i = 0; i < optionalNum; i++) {
            String optionalBlockID = Strings.decode(new byte[]{tr31[index++], tr31[index++]});
            int optionalBlockLength = Integer.parseInt(Strings.decode(new byte[]{tr31[index++], tr31[index++]}), 16);
            String optionalBlockData = Strings.decode(Bytes.subBytes(tr31, index, optionalBlockLength - 4));
            index += optionalBlockLength - 4;
            PrintfUtil.d("OptionalBlockID", optionalBlockID);
            OptionalBlock optionalBlock = new OptionalBlock(optionalBlockData);
            addOptionalBlock(optionalBlockID, optionalBlock);
            if (optionalBlockID.equals(OptionalBlockID.KS)) {
                PrintfUtil.d("KSN", optionalBlockData);
            } else if (optionalBlockID.equals(OptionalBlockID.KP)) {
                PrintfUtil.d("KBPK KCV", optionalBlockData.substring(2));
            } else if (optionalBlockID.equals(OptionalBlockID.KC)) {
                PrintfUtil.d("KCV", optionalBlockData.substring(2));
            } else {
                PrintfUtil.d("OptionalBlockData", optionalBlockData);
            }
        }
        // Mac长度
        int macLen = 0;
        // KeyHead
        keyHead = Bytes.subBytes(tr31, 0, index);
        PrintfUtil.d("KeyHead", Bytes.toHexString(keyHead));
        if (keyBlockVersion == KeyBlockVersion.B) {
            macLen = KEY_BLOCK_VERSION_B_MAC_LENGTH;
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            macLen = KEY_BLOCK_VERSION_D_MAC_LENGTH;
        }
        // Out
        byte[] out_ascii = Bytes.subBytes(tr31, index, tr31.length - index - macLen);
        PrintfUtil.d("Out-ASCII", Bytes.toHexString(out_ascii));
        out = Bytes.fromHexString(Strings.decode(out_ascii));
        PrintfUtil.d("Out", Bytes.toHexString(out));
        // Mac
        byte[] mac_ascii = Bytes.subBytes(tr31, tr31.length - macLen, macLen);
        PrintfUtil.d("Mac-ASCII", Bytes.toHexString(mac_ascii));
        mac = Bytes.fromHexString(Strings.decode(mac_ascii));
        PrintfUtil.d("Mac", Bytes.toHexString(mac));
        // KeyBolck
        byte[] encKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            encKey = desDeriveEncKey(bpk);
            keyBlock = AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.TDES, AlgUtil.AlgorithmModel.CBC,
                    AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, out);
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            encKey = aesDeriveEncKey(bpk);
            keyBlock = AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.AES, AlgUtil.AlgorithmModel.CBC,
                    AlgUtil.SymmetryPadding.ZeroPadding, encKey, mac, out);
        }
        PrintfUtil.d("EncKey", Bytes.toHexString(encKey));
        PrintfUtil.d("KeyBlock", Bytes.toHexString(keyBlock));
        // 释放
        Arrays.fill(encKey, (byte) 0x00);
        // Key
        int keyLen = Bytes.toInt(new byte[]{keyBlock[0], keyBlock[1]}) / 8;
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
        byte[] checkMac = null;
        // 校验MAC
        byte[] macKey = null;
        if (keyBlockVersion == KeyBlockVersion.B) {
            macKey = desDeriveMacKey(bpk);
            checkMac = AlgUtil.tdesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
        } else if (keyBlockVersion == KeyBlockVersion.D) {
            macKey = aesDeriveMacKey(bpk);
            checkMac = AlgUtil.aesCMAC(macKey, Bytes.concat(keyHead, keyBlock));
            // 释放
            Arrays.fill(macKey, (byte) 0x00);
        }
        PrintfUtil.d("MacKey", Bytes.toHexString(macKey));
        PrintfUtil.d("CheckMac", Bytes.toHexString(checkMac));
        // 释放
        Arrays.fill(macKey, (byte) 0x00);
        if (!Bytes.equals(checkMac, mac)) {
            PrintfUtil.e("TR31", "Check Mac error");
            throw new IllegalArgumentException("Check Mac error");
        }
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
     *
     * @return
     */
    private boolean checkKeyUsageAndModeOfUse() {
        Map<String, String[]> map = new HashMap<>();
        map.put("01", new String[]{ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.BDK, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DUKPT_INIT_KEY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.BASE_KEY_VARIANT_KEY, new String[]{ModeOfUse.CREATE_KEY_VARIANTS + ""});
        map.put(KeyUsage.CVK, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.SYMMETRIC_KEY_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.DECIMALIZATION_TABLE_DATA_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.APPLICATION_CRYPTOGRAMS, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.MESSAGING_FOR_CONFIDENTIALITY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.MESSAGING_FOR_INTEGRITY, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DATA_AUTHENTICATION_CODE, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.DYNAMIC_NUMBERS, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.CARD_PERSONALIZATION, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.OTHER, new String[]{ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.IV, new String[]{ModeOfUse.NO_RESTRICTIONS + ""});
        map.put(KeyUsage.KEY_ENC_OR_WRAP, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.TR31_PROTECTION_KEY, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.TR34_ASYMMETRIC_KEY, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_AGREE_WRAP, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + "", ModeOfUse.DERIVE_KEYS + ""});
        map.put(KeyUsage.ISO_16609_MAC_ALGORITHM_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_2, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_3, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_MAC_Algorithm_4, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_1999_MAC_ALGORITHM_5, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.CMAC, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.HMAC, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.ISO_9797_1_2011_MAC_ALGORITHM_6, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.PIN_ENCRYPTION, new String[]{ModeOfUse.ENC_DEC_WRAP_UNWRAP + "",
                ModeOfUse.DEC_OR_UNWRAP_ONLY + "", ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.ASYMMETRIC_KEY_SIGNATURE,
                new String[]{ModeOfUse.SIGNATURE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.LOG_SIGNATURE, new String[]{ModeOfUse.SIGNATURE_ONLY + ""});
        map.put(KeyUsage.CA, new String[]{ModeOfUse.SIGNATURE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.NONX9_24,
                new String[]{ModeOfUse.SIGNATURE_ONLY + "", ModeOfUse.VERIFY_ONLY + "", ModeOfUse.SIGN_AND_DEC + "",
                        ModeOfUse.ENC_DEC_WRAP_UNWRAP + "", ModeOfUse.DEC_OR_UNWRAP_ONLY + "",
                        ModeOfUse.ENC_OR_WRAP_ONLY + ""});
        map.put(KeyUsage.KPV, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.IBM_3624, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.VISA_PVV, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "", ModeOfUse.GENERATE_ONLY + "",
                ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.X9_132_ALGORITHM_1, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        map.put(KeyUsage.X9_132_ALGORITHM_2, new String[]{ModeOfUse.GENERATE_AND_VERIFY + "",
                ModeOfUse.GENERATE_ONLY + "", ModeOfUse.VERIFY_ONLY + ""});
        if (map.get(keyUsage) == null) {
            throw new IllegalArgumentException("KeyUsage error");
        } else {
            String[] values = map.get(keyUsage);
            List<String> modeOfUses = Arrays.asList(values);
            return modeOfUses.contains(modeOfUse + "");
        }
    }
}
