package com.biapp.utils;

import android.content.Context;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;
import android.telephony.TelephonyManager;
import android.text.TextUtils;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.TimeZone;

/**
 * @author Yun
 */
public class DeviceInfoUtil {

    /***
     * 获得CPU架构
     *
     * @return
     */
    public static String getCPU() {
        String cpu = "";
        if (!TextUtils.isEmpty(android.os.Build.CPU_ABI)) {
            cpu += android.os.Build.CPU_ABI;
        }
        if (!TextUtils.isEmpty(android.os.Build.CPU_ABI2)) {
            cpu += "," + android.os.Build.CPU_ABI2;
        }
        return cpu;
    }

    /**
     * 是否有SD卡
     *
     * @return
     */
    public static boolean haveSDCard() {
        if (Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
            return true;
        }
        return false;
    }

    /**
     * 获取SD卡的总大小
     *
     * @return
     */
    public static long getSDCardTotalSize() {
        long total = 0;
        try {
            if (haveSDCard()) {
                File path = Environment.getExternalStorageDirectory();
                StatFs statfs = new StatFs(path.getPath());
                long blocSize = statfs.getBlockSize();
                long totalBlocks = statfs.getBlockCount();
                total = totalBlocks * blocSize;
            }
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return total;
    }

    /**
     * 获取内部可用空间大小
     *
     * @return
     */
    public static long getDataAvailableSize() {
        long available = 0;
        File path = Environment.getDataDirectory();
        StatFs statfs = new StatFs(path.getPath());
        long blocSize = statfs.getBlockSize();
        long availaBlock = statfs.getAvailableBlocks();
        available = availaBlock * blocSize;
        return available;
    }

    /**
     * 获取SD卡的可用空间大小
     *
     * @return
     */
    public static long getSDCardAvailableSize() {
        long available = 0;
        try {
            if (haveSDCard()) {
                File path = Environment.getExternalStorageDirectory();
                StatFs statfs = new StatFs(path.getPath());
                long blocSize = statfs.getBlockSize();
                long availaBlock = statfs.getAvailableBlocks();
                available = availaBlock * blocSize;
            }
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return available;
    }

    /**
     * 获得版本（手机型号）
     *
     * @return
     */
    public static String getModel() {
        String model = "";
        if (TextUtils.isEmpty(android.os.Build.MODEL)) {
            return model;
        }
        model = android.os.Build.MODEL;
        return model;
    }

    /**
     * 获得安卓系统定制商(品牌)
     *
     * @return
     */
    public static String getBrand() {
        String brand = "";
        if (TextUtils.isEmpty(android.os.Build.BRAND)) {
            return brand;
        }
        brand = android.os.Build.BRAND;
        return brand;
    }

    /**
     * 获得安卓SDK
     *
     * @return
     */
    public static int getSdk() {
        return android.os.Build.VERSION.SDK_INT;
    }

    /**
     * 获得安卓版本
     *
     * @return
     */
    public static String getRelease() {
        String release = "";
        if (TextUtils.isEmpty(android.os.Build.VERSION.RELEASE)) {
            return release;
        }
        release = android.os.Build.VERSION.RELEASE;
        return release;
    }

    /**
     * 获得IMEI号（需要android.permission.READ_PHONE_STATE权限）
     *
     * @param context Context
     * @return
     */
    public static String getIMEI(Context context) {
        String imei = "";
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (null == manager || TextUtils.isEmpty(manager.getDeviceId())) {
            return imei;
        }
        if (!TextUtils.isEmpty(manager.getDeviceId())) {
            imei = manager.getDeviceId();
        }
        return imei;
    }

    /**
     * 获得IMSI号（需要android.permission.READ_PHONE_STATE权限）
     *
     * @param context Context
     * @return
     */
    public static String getIMSI(Context context) {
        String imsi = "";
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (null == manager || TextUtils.isEmpty(manager.getSubscriberId())) {
            return imsi;
        }
        imsi = manager.getSubscriberId();
        return imsi;
    }

    /**
     * 获得手机号（需要android.permission.READ_PHONE_STATE权限）
     *
     * @param context Context
     * @return
     */
    public static String getPhoneNumber(Context context) {
        String phone = "";
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (null == manager || TextUtils.isEmpty(manager.getLine1Number())) {
            return phone;
        }
        phone = manager.getLine1Number();
        return phone;
    }

    /**
     * 获取SIM卡提供商名称（需要android.permission.READ_PHONE_STATE权限）
     *
     * @param context Context
     * @return
     */
    public static String getSimOperatorName(Context context) {
        String operator = "";
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (null == manager || TextUtils.isEmpty(manager.getSimOperatorName())) {
            return operator;
        }
        operator = manager.getSimOperatorName();
        return operator;
    }

    /**
     * 获得网络类型（需要android.permission.ACCESS_NETWORK_STATE权限）
     *
     * @param context Context
     * @return
     */
    public static String getNetType(Context context) {
        // 默认值0
        String netType = "0";
        // Wifi网络
        if (isWiFiNet(context)) {
            netType = "10";
            return netType;
        }
        // 移动网络
        TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (null == manager) {
            return netType;
        }
        switch (manager.getNetworkType()) {
            case TelephonyManager.NETWORK_TYPE_UNKNOWN:
                netType = "0";
                break;
            case TelephonyManager.NETWORK_TYPE_1xRTT:
            case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_GPRS:
            case TelephonyManager.NETWORK_TYPE_IDEN:
            case TelephonyManager.NETWORK_TYPE_EDGE:
                netType = "2";
                break;
            case TelephonyManager.NETWORK_TYPE_EHRPD:
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_EVDO_B:
            case TelephonyManager.NETWORK_TYPE_HSDPA:
            case TelephonyManager.NETWORK_TYPE_HSPA:
            case TelephonyManager.NETWORK_TYPE_HSPAP:
            case TelephonyManager.NETWORK_TYPE_HSUPA:
            case TelephonyManager.NETWORK_TYPE_UMTS:
            case TelephonyManager.NETWORK_TYPE_LTE:
                netType = "4";
                break;
            default:
                netType = "0";
                break;
        }
        return netType;
    }

    /**
     * 获得当前地区或国家
     *
     * @return
     */
    public static String getCountry() {
        String contury = "";
        if (TextUtils.isEmpty(Locale.getDefault().getCountry())) {
            return contury;
        }
        contury = Locale.getDefault().getCountry();
        return contury;
    }

    /**
     * 获得当前语言
     *
     * @return
     */
    public static String getLanguage() {
        String language = "";
        if (TextUtils.isEmpty(Locale.getDefault().getLanguage())) {
            return language;
        }
        language = Locale.getDefault().getLanguage();
        return language;
    }

    /***
     * 获得时区
     *
     * @return
     */
    public static String getTimeZone() {
        String timezone = "";
        timezone = TimeZone.getDefault().getDisplayName(false, TimeZone.SHORT, Locale.ENGLISH);
        return timezone;
    }

    /**
     * 网络是否连接
     *
     * @param context Context
     * @return
     */
    public static boolean isNetworkConncet(Context context) {
        boolean conncet = false;
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager != null) {
            NetworkInfo network = manager.getActiveNetworkInfo();
            if (network != null) {
                conncet = network.isAvailable();
            }
        }
        return conncet;
    }

    /**
     * 判断是否为WiFi网络 （需要 android.permission.ACCESS_NETWORK_STATE、
     * android.permission.ACCESS_WIFI_STATE 权限）
     *
     * @param context Context
     * @return
     */
    public static boolean isWiFiNet(Context context) {
        boolean wifi = false;
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (null == manager) {
            return wifi;
        }
        NetworkInfo info = manager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (null == info) {
            return wifi;
        }
        if (info.isConnected()) {
            wifi = true;
        }
        return wifi;
    }

    /**
     * 获得屏幕密度
     *
     * @param context Context
     * @return
     */
    public static float getScreenDensity(Context context) {
        float density = 0.0f;
        density = context.getResources().getDisplayMetrics().density;
        return density;
    }

    /**
     * 获得屏幕宽度
     *
     * @param context Context
     * @return 像素
     */
    public static int getScreenWidth(Context context) {
        int width = 0;
        width = context.getResources().getDisplayMetrics().widthPixels;
        return width;
    }

    /**
     * 获得屏幕高度
     *
     * @param context Context
     * @return 像素
     */
    public static int getScreenHeight(Context context) {
        int height = 0;
        height = context.getResources().getDisplayMetrics().heightPixels;
        return height;
    }

    /***
     * 判断是否横屏
     *
     * @param context
     * @return
     */
    public static boolean isHorizontalScreen(Context context) {
        // 获取设置的配置信息
        Configuration mConfiguration = context.getResources().getConfiguration();
        // 获取屏幕方向
        int ori = mConfiguration.orientation;
        if (ori == Configuration.ORIENTATION_LANDSCAPE) {
            // 横屏
            return true;
        } else if (ori == Configuration.ORIENTATION_PORTRAIT) {
            // 竖屏
            return false;
        }
        return false;
    }

    /****
     * 是否是Pad
     * @param context
     * @return
     */
    public static boolean isPad(Context context) {
        // 屏幕尺寸
        double x = Math.pow(context.getResources().getDisplayMetrics().widthPixels / context.getResources().getDisplayMetrics().xdpi, 2);
        double y = Math.pow(context.getResources().getDisplayMetrics().heightPixels / context.getResources().getDisplayMetrics().ydpi, 2);
        double screenInches = Math.sqrt(x + y);
        // 大于6寸则为Pad
        return screenInches >= 6.0 ? true : false;
    }

    /**
     * 是否亮屏幕
     *
     * @param context
     * @return
     */
    public static boolean isScreenOn(Context context) {
        PowerManager powerManager = (PowerManager) context
                .getSystemService(Context.POWER_SERVICE);
        return powerManager.isScreenOn();
    }

    /**
     * 获得IP地址
     *
     * @param context
     * @return
     */
    public static String getIpAddress(Context context) {
        String ipAddress = "0.0.0.0";
        try {
            NetworkInfo info = ((ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
            if (info != null && info.isConnected()) {
                // 3/4g网络
                if (info.getType() == ConnectivityManager.TYPE_MOBILE) {
                    for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                        NetworkInterface intf = en.nextElement();
                        for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                            InetAddress inetAddress = enumIpAddr.nextElement();
                            if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                                ipAddress = inetAddress.getHostAddress();
                            }
                        }
                    }
                } else if (info.getType() == ConnectivityManager.TYPE_WIFI) {
                    //  wifi网络
                    WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
                    WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                    int ip = wifiInfo.getIpAddress();
                    ipAddress = (ip & 0xFF) + "." +
                            ((ip >> 8) & 0xFF) + "." +
                            ((ip >> 16) & 0xFF) + "." +
                            (ip >> 24 & 0xFF);
                }
                // 有限网络
                else if (info.getType() == ConnectivityManager.TYPE_ETHERNET) {
                    for (Enumeration<NetworkInterface> en = NetworkInterface
                            .getNetworkInterfaces(); en.hasMoreElements(); ) {
                        NetworkInterface intf = en.nextElement();
                        for (Enumeration<InetAddress> enumIpAddr = intf
                                .getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                            InetAddress inetAddress = enumIpAddr.nextElement();
                            if (!inetAddress.isLoopbackAddress()
                                    && inetAddress instanceof Inet4Address) {
                                ipAddress = inetAddress.getHostAddress();
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return ipAddress;
    }

}
