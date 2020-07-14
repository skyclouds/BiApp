package com.biapp.util;

import android.text.TextUtils;

import java.math.BigDecimal;

/**
 * @author Yun
 */
public class FormatUtil {

    public final static long BYTE = 1;
    public final static long KB = 1024 * BYTE;
    public final static long MB = 1024 * KB;
    public final static long GB = 1024 * MB;
    public final static long TB = 1024 * GB;

    /**
     * 格式化数据大小
     *
     * @param size 大小
     * @return 返回格式化数据
     */
    public static String formatDataSize(long size) {
        // 格式化数据
        String format = "";
        if (0 == size) {
            return format;
        }
        double byteSize = 0;
        if (size < KB) {
            byteSize = size / (BYTE * 1.0);
            format = roundUp(byteSize) + " Byte";
        } else if (size < MB) {
            byteSize = size / (KB * 1.0);
            format = roundUp(byteSize) + " KB";
        } else if (size < GB) {
            byteSize = size / (MB * 1.0);
            format = roundUp(byteSize) + " MB";
        } else if (size < TB) {
            byteSize = size / (GB * 1.0);
            format = roundUp(byteSize) + " GB";
        } else {
            byteSize = size / (TB * 1.0);
            format = roundUp(byteSize) + " TB";

        }
        return format;
    }

    /**
     * @param appendChar
     * @param length
     * @return
     */
    public static String addAppend(char appendChar, int length, String data) {
        StringBuffer append = new StringBuffer();
        int dataLength = TextUtils.isEmpty(data) ? 0 : data.length();
        if (!TextUtils.isEmpty(data)) {
            append.append(data);
        }
        for (int i = 0; i < length - dataLength; i++) {
            append.append(appendChar);
        }
        return append.toString();
    }

    /**
     * @param headChar
     * @param length
     * @return
     */
    public static String addHead(char headChar, int length, String data) {
        StringBuffer head = new StringBuffer();
        int dataLength = TextUtils.isEmpty(data) ? 0 : data.length();
        for (int i = 0; i < length - dataLength; i++) {
            head.append(headChar);
        }
        if (!TextUtils.isEmpty(data)) {
            head.append(data);
        }
        return head.toString();
    }

    /**
     * 四舍五入(保留2位)
     *
     * @param value
     * @return
     */
    public static double roundUp(double value) {
        BigDecimal decimal = new BigDecimal(value);
        return decimal.setScale(2, BigDecimal.ROUND_HALF_UP).doubleValue();
    }

    /**
     * #.##格式化
     *
     * @param value
     * @ret
     */
    public static String getDoubelString(double value) {
        return String.format("%.2f", value);
    }

    /**
     * 去除所有空格
     *
     * @param str
     * @return
     */
    public static String removeAllSpace(String str) {
        return str.replaceAll(" +", "").replaceAll("\\s", "").replaceAll("\\t", "");
    }

    /**
     * 去除字符串首尾出现的某个字符.
     *
     * @param source  源字符串.
     * @param element 需要去除的字符.
     * @return String.
     */
    public static String trimFirstAndLastChar(String source, char element) {
        boolean beginIndexFlag = true;
        boolean endIndexFlag = true;
        do {
            int beginIndex = source.indexOf(element) == 0 ? 1 : 0;
            int endIndex = source.lastIndexOf(element) + 1 == source.length() ? source.lastIndexOf(element) : source.length();
            source = source.substring(beginIndex, endIndex);
            beginIndexFlag = (source.indexOf(element) == 0);
            endIndexFlag = (source.lastIndexOf(element) + 1 == source.length());
        } while (beginIndexFlag || endIndexFlag);
        return source;
    }

    /**
     * 去除ini文件中的注释，以";"或"#"开头，顺便去除UTF-8等文件的BOM头
     *
     * @param source
     * @return
     */
    public static String removeIniComments(String source) {
        String result = source;
        if (result.contains(";")) {
            result = result.substring(0, result.indexOf(";"));
        }
        if (result.contains("#")) {
            result = result.substring(0, result.indexOf("#"));
        }
        return result.trim();
    }
}
