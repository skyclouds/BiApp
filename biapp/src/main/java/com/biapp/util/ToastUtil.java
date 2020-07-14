package com.biapp.util;

import android.content.Context;
import android.view.Gravity;
import android.widget.Toast;

/**
 * @author Yun
 */
public class ToastUtil {
    private static Toast toast;

    private ToastUtil() {
    }

    public static void showShort(Context context, int msgId) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_SHORT);
        }
        showToast(context.getString(msgId), Toast.LENGTH_SHORT, false);
    }

    public static void showShort(Context context, String msg) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_SHORT);
        }
        showToast(msg, Toast.LENGTH_SHORT, false);
    }


    public static void showLong(Context context, int msgId) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_LONG);
        }
        showToast(context.getString(msgId), Toast.LENGTH_LONG, false);
    }

    public static void showLong(Context context, int msgId, boolean isCenter) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_LONG);
        }
        showToast(context.getString(msgId), Toast.LENGTH_LONG, isCenter);
    }


    public static void showLong(Context context, String msg) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_LONG);
        }
        showToast(msg, Toast.LENGTH_LONG, false);
    }

    public static void showLong(Context context, String msg, boolean isCenter) {
        if (toast == null) {
            toast = Toast.makeText(context, "", Toast.LENGTH_LONG);
        }
        showToast(msg, Toast.LENGTH_LONG, isCenter);
    }

    private static void showToast(String msg, int duration, boolean isCenter) {
        toast.setText(msg);
        toast.setDuration(duration);
        if (isCenter) {
            toast.setGravity(Gravity.CENTER, 0, 0);
        }
        toast.show();
    }
}
