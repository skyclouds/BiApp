package com.biapp.utils;


import timber.log.Timber;


/**
 * @author Yun
 */
public class PrintfUtil {

    /**
     * 打印Hex
     *
     * @param tag
     * @param hex
     */
    public static void d(String tag, String hex) {
        int max = 2048;
        int round = hex.length() / max;
        //小于1024
        if (round == 0) {
            Timber.d(tag, hex);
        } else {
            for (int i = 0; i < round; i++) {
                Timber.d(tag + "(" + (round + 1) + ")%s", hex.substring(i * max, (i + 1) * max));
            }
            if (hex.length() % max != 0) {
                Timber.d(tag + "(" + (round + 1) + ")%s", hex.substring(round * max));
            }
        }
    }
}
