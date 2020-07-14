package com.biapp.util;


import aura.data.Bytes;
import timber.log.Timber;


/**
 * @author Yun
 */
public class PrintfUtil {

    /**
     * 打印
     *
     * @param tag
     * @param hex
     */
    public static void hex(String tag, String hex) {
        int max = 16;
        int round = hex.length() / max;
        //小于16
        if (round == 0) {
            Timber.d("[" + tag + "]%s", FormatUtil.addAppend(' ', 32, Bytes.toHexString(hex.getBytes())) + " |/*" + hex + "*/|");
        } else {
            for (int i = 0; i < round; i++) {
                Timber.d("[" + tag + "(" + String.format("%04d", i + 1) + ")" + "]%s", FormatUtil.addAppend(' ', 32, Bytes.toHexString(hex.substring(i * max, (i + 1) * max).getBytes())) + " |/*" + hex.substring(i * max, (i + 1) * max) + "*/|");
            }
            if (hex.length() % max != 0) {
                Timber.d("[" + tag + "(" + String.format("%04d", round + 1) + ")" + "]%s", FormatUtil.addAppend(' ', 32, Bytes.toHexString(hex.substring(round * max).getBytes())) + " |/*" + hex.substring(round * max) + "*/|");
            }
        }
    }

    /**
     * 打印(超过2K)
     *
     * @param tag
     * @param log
     */
    public static void i(String tag, String log) {
        int max = 2048;
        int round = log.length() / max;
        //小于1024
        if (round == 0) {
            Timber.i("[" + tag + "]%s", log);
        } else {
            for (int i = 0; i < round; i++) {
                Timber.i("[" + tag + "(" + (i + 1) + ")" + "]%s", log.substring(i * max, (i + 1) * max));
            }
            if (log.length() % max != 0) {
                Timber.i("[" + tag + "(" + (round + 1) + ")" + "]%s", log.substring(round * max));
            }
        }
    }

    /**
     * 打印(超过2K)
     *
     * @param tag
     * @param log
     */
    public static void d(String tag, String log) {
        int max = 2048;
        int round = log.length() / max;
        //小于1024
        if (round == 0) {
            Timber.d("[" + tag + "]%s", log);
        } else {
            for (int i = 0; i < round; i++) {
                Timber.d("[" + tag + "(" + (i + 1) + ")" + "]%s", log.substring(i * max, (i + 1) * max));
            }
            if (log.length() % max != 0) {
                Timber.d("[" + tag + "(" + (round + 1) + ")" + "]%s", log.substring(round * max));
            }
        }
    }

    /**
     * 打印(超过2K)
     *
     * @param tag
     * @param log
     */
    public static void w(String tag, String log) {
        int max = 2048;
        int round = log.length() / max;
        //小于1024
        if (round == 0) {
            Timber.w("[" + tag + "]%s", log);
        } else {
            for (int i = 0; i < round; i++) {
                Timber.w("[" + tag + "(" + (i + 1) + ")" + "]%s", log.substring(i * max, (i + 1) * max));
            }
            if (log.length() % max != 0) {
                Timber.w("[" + tag + "(" + (round + 1) + ")" + "]%s", log.substring(round * max));
            }
        }
    }

    /**
     * @param t
     */
    public static void e(Throwable t) {
        Timber.e(t);
    }

    /**
     * 打印(超过2K)
     *
     * @param tag
     * @param err
     */
    public static void e(String tag, String err) {
        int max = 2048;
        int round = err.length() / max;
        //小于1024
        if (round == 0) {
            Timber.e("[" + tag + "]%s", err);
        } else {
            for (int i = 0; i < round; i++) {
                Timber.e("[" + tag + "(" + (round + 1) + ")" + "]%s", err.substring(i * max, (i + 1) * max));
            }
            if (err.length() % max != 0) {
                Timber.e("[" + tag + "(" + (round + 1) + ")" + "]%s", err.substring(round * max));
            }
        }
    }
}
