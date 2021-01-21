package com.biapp.util;

import java.util.ArrayList;
import java.util.List;

import aura.data.Bytes;

/**
 * @author yun
 */
public class TLVUtil {

    /**
     * @author yun
     */
    public static class TLV {
        private byte[] tag;
        private int length;
        private byte[] lenBytes;
        private byte[] value;
        private List<TLV> children = new ArrayList<>();

        public TLV(byte[] tag, byte[] lenBytes, int length, byte[] value) {
            this.tag = tag;
            this.lenBytes = lenBytes;
            this.length = length;
            this.value = value;
        }

        public byte[] getTag() {
            return tag;
        }

        public void setTag(byte[] tag) {
            this.tag = tag;
        }

        public int getLength() {
            return length;
        }

        public void setLength(int length) {
            this.length = length;
        }

        public byte[] getValue() {
            return value;
        }

        public void setValue(byte[] value) {
            this.value = value;
        }

        public List<TLV> getChildren() {
            return children;
        }

        public void setChildren(List<TLV> children) {
            this.children = children;
        }

        public boolean hasChildren() {
            return !this.children.isEmpty();
        }

        @Override
        public String toString() {
            return Bytes.toHexString(Bytes.concat(tag, lenBytes, value));
        }

        public byte[] getBytes(){
            return Bytes.concat(tag, lenBytes, value);
        }
    }

    /**
     * 解析DER TLV
     *
     * @param tlvData
     * @return
     */
    public static List<TLV> parseDER(byte[] tlvData) throws IllegalArgumentException {
        List<TLV> tlvs = new ArrayList<TLV>();
        for (int i = 0; i < tlvData.length; ) {
            byte[] tag = new byte[]{tlvData[i++]};
            if (Bytes.equals(tag, new byte[]{0x00})) {
                continue;
            } else if (Bytes.equals(tag, new byte[]{0x30}) || Bytes.equals(tag, new byte[]{0x02})
                    || Bytes.equals(tag, new byte[]{0x03}) || Bytes.equals(tag, new byte[]{0x04})
                    || Bytes.equals(tag, new byte[]{(byte) 0xA0}) || Bytes.equals(tag, new byte[]{(byte) 0xA3})) {
                byte[] lengthData = new byte[]{tlvData[i++]};
                int length = lengthData[0] & 0xFF;
                if (length > 0x80) {
                    int lengthLen = length & 0x7F;
                    lengthData = Bytes.concat(lengthData, Bytes.subBytes(tlvData, i, lengthLen));
                    length = Bytes.toInt(Bytes.subBytes(tlvData, i, lengthLen));
                    i += lengthLen;
                }
                byte[] value = Bytes.subBytes(tlvData, i, length);
                if (value.length != length) {
                    throw new IllegalArgumentException("parse DER error");
                }
                i += length;
                TLV tlv = new TLV(tag, lengthData, length, value);
                if (Bytes.equals(tag, new byte[]{0x30}) || Bytes.equals(tag, new byte[]{0x03})
                        || Bytes.equals(tag, new byte[]{(byte) 0x04})
                        || Bytes.equals(tag, new byte[]{(byte) 0xA3})) {
                    tlv.setChildren(parseDER(value));
                }
                tlvs.add(tlv);
            } else {
                break;
            }
        }
        return tlvs;
    }

}