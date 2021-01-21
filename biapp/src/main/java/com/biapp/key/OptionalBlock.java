package com.biapp.key;

/**
 * @author yun
 */
public class OptionalBlock {
    /**
     * Optional Block Length(2H)
     */
    private String length;

    /**
     * Optional Block Data(PA)
     */
    private String data;

    public OptionalBlock(String data) {
        this.data = data;
    }

    public String getLength() {
        //OptionalBlock ID(2AN)+Optional Block Length(2H)+Optional Block Data(PA)
        return String.format("%02x", 2 + 2 + data.length()).toUpperCase();
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
