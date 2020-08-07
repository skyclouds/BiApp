package com.biapp.key;

import com.biapp.util.FormatUtil;

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

    public OptionalBlock(String data){
        this.data=data;
    }

    public String getLength() {
        //OptionalBlock ID(2AN)+Optional Block Length(2H)+Optional Block Data(PA)
        return FormatUtil.addHead('0',2,Integer.toHexString(2+2+data.length()));
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
