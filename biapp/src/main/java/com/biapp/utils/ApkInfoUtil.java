package com.biapp.utils;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import aura.data.Bytes;


/**
 * @author Yun
 */
public class ApkInfoUtil {

    /****
     * 创建Context
     * @param context
     * @param packageName
     * @return
     */
    public static Context createContext(Context context, String packageName) {
        Context createContext = null;
        try {
            createContext = context.createPackageContext(packageName, Context.CONTEXT_IGNORE_SECURITY);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return createContext;
    }

    public static File getApk(Context context, String packageName) {
        File apk = null;
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager != null) {
                ApplicationInfo applicationInfo = packageManager.getApplicationInfo(packageName, 0);
                if (applicationInfo != null) {
                    apk = new File(applicationInfo.sourceDir);
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return apk;
    }

    /**
     * 获得图标
     *
     * @param context
     * @return
     */
    public static Drawable getIconDrawable(Context context) {
        return getIconDrawable(context, context.getPackageName());
    }

    /***
     * 获得图标
     *
     * @param context
     * @param packageName
     * @return
     */
    public static Drawable getIconDrawable(Context context, String packageName) {
        Drawable drawable = null;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    if (packageInfo.applicationInfo != null) {
                        drawable = packageManager.getApplicationIcon(packageInfo.applicationInfo);
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return drawable;
    }

    /***
     * 获得图标
     *
     * @param context
     * @param file
     *            文件
     * @return
     */
    public static Drawable getIconDrawable(Context context, File file) {
        Drawable drawable = null;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                if (packageInfo.applicationInfo != null) {
                    drawable = packageManager.getApplicationIcon(packageInfo.applicationInfo);
                }
            }
        }
        return drawable;
    }

    /**
     * 获得应用名称
     *
     * @param context
     * @return
     */
    public static String getAppName(Context context) {
        return getAppName(context, context.getPackageName());
    }


    /***
     * 获得应用名称
     *
     * @param context
     * @param packageName
     * @return
     */
    public static String getAppName(Context context, String packageName) {
        // 应用名称
        String appName = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    if (packageInfo.applicationInfo != null) {
                        appName = packageManager.getApplicationLabel(packageInfo.applicationInfo).toString();
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return appName;
    }

    /***
     * 获得应用名称
     *
     * @param context
     * @param file
     *            文件
     * @return
     */
    public static String getAppName(Context context, File file) {
        // 应用名称
        String appName = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                if (packageInfo.applicationInfo != null) {
                    appName = packageManager.getApplicationLabel(packageInfo.applicationInfo).toString();
                }
            }
        }
        return appName;
    }

    /***
     * 获得应用包名
     *
     * @param context
     * @return
     */
    public static String getPackageName(Context context) {
        return context.getPackageName();
    }

    /***
     * 获得应用包名
     *
     * @param context
     * @param file
     *            文件
     * @return
     */
    public static String getPackageName(Context context, File file) {
        String packageName = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                packageName = packageInfo.packageName;
            }
        }
        return packageName;
    }

    /**
     * 获得应用版本名称
     *
     * @param context
     * @return
     */
    public static String getVersionName(Context context) {
        return getVersionName(context, context.getPackageName());
    }

    /**
     * 获得应用版本名称
     *
     * @param context
     * @param packageName
     * @return
     */
    public static String getVersionName(Context context, String packageName) {
        // 版本名称
        String versionName = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    versionName = packageInfo.versionName;
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return versionName;
    }

    /***
     * 获得应用版本名称
     *
     * @param context
     * @param file
     *            文件
     * @return
     */
    public static String getVersionName(Context context, File file) {
        // 版本名称
        String versionName = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                versionName = packageInfo.versionName;
            }
        }
        return versionName;
    }

    /**
     * 获得应用版本号
     *
     * @param context
     * @return
     */
    public static int getVersionCode(Context context) {
        return getVersionCode(context, context.getPackageName());
    }

    /**
     * 获得应用版本号
     *
     * @param context
     * @param packageName
     * @return
     */
    public static int getVersionCode(Context context, String packageName) {
        // 版本号
        int versionCode = -1;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    versionCode = packageInfo.versionCode;
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return versionCode;
    }

    /***
     * 获得应用版本号
     *
     * @param context
     * @param file
     *            文件
     * @return
     */
    public static int getVersionCode(Context context, File file) {
        int versionCode = -1;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                versionCode = packageInfo.versionCode;
            }
        }
        return versionCode;
    }

    /**
     * 获取签名信息
     *
     * @param context
     * @return
     */
    public static String getSign(Context context) {
        return getSign(context, context.getPackageName());
    }


    /**
     * 获取签名信息
     *
     * @param context     Context
     * @param packageName
     * @return
     */
    public static String getSign(Context context, String packageName) {
        // 签名
        String sign = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                if (packageInfo != null) {
                    if ((packageInfo.signatures != null) && (packageInfo.signatures.length > 0)) {
                        sign = packageInfo.signatures[0].toCharsString();
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return sign;
    }

    /**
     * 获取签名信息
     *
     * @param context Context
     * @param file    文件
     * @return
     */
    public static String getSign(Context context, File file) {
        // 签名
        String sign = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_SIGNATURES);
            if (packageInfo != null) {
                if ((packageInfo.signatures != null) && (packageInfo.signatures.length > 0)) {
                    sign = packageInfo.signatures[0].toCharsString();
                }
            }
        }
        return sign;
    }

    /**
     * 获取权限信息
     *
     * @param context
     * @return
     */
    public static List<String> getPermissions(Context context) {
        return getPermissions(context, context.getPackageName());
    }

    /**
     * 获取权限信息
     *
     * @param context     Context
     * @param packageName
     * @return
     */
    public static List<String> getPermissions(Context context, String packageName) {
        // 权限
        List<String> permissionsList = new ArrayList<String>();
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS);
                if (packageInfo != null) {
                    String[] permissions = packageInfo.requestedPermissions;
                    if (permissions != null && permissions.length > 0) {
                        for (String permission : permissions) {
                            permissionsList.add(permission);
                        }
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return permissionsList;
    }

    /**
     * 获取权限信息
     *
     * @param context Context
     * @param file    文件
     * @return
     */
    public static List<String> getPermissions(Context context, File file) {
        // 权限
        List<String> permissionsList = new ArrayList<String>();
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_PERMISSIONS);
            if (packageInfo != null) {
                String[] permissions = packageInfo.requestedPermissions;
                if (permissions != null && permissions.length > 0) {
                    for (String permission : permissions) {
                        permissionsList.add(permission);
                    }
                }
            }
        }
        return permissionsList;
    }

    /***
     * 获得已安装应用包名
     *
     * @param context
     * @return
     */
    public static List<String> getInstalledPackageName(Context context) {
        List<String> list = new ArrayList<>();
        PackageManager packageManager = context.getPackageManager();
        List<PackageInfo> packageInfos = packageManager.getInstalledPackages(PackageManager.PERMISSION_GRANTED);
        if (packageInfos != null && !packageInfos.isEmpty()) {
            for (PackageInfo packageInfo : packageInfos) {
                //过滤系统应用
                if ((ApplicationInfo.FLAG_SYSTEM & packageInfo.applicationInfo.flags) != 0) {
                    continue;
                }
                list.add(packageInfo.packageName);
            }
        }
        return list;
    }

    /***
     * 是否安装了应用
     *
     * @param context
     * @param packageName
     * @return
     */
    public static boolean hasInstalled(Context context, String packageName) {
        boolean install = false;
        PackageManager packageManager = context.getPackageManager();
        List<PackageInfo> packageInfos = packageManager.getInstalledPackages(PackageManager.PERMISSION_GRANTED);
        if (packageInfos != null && !packageInfos.isEmpty()) {
            for (PackageInfo packageInfo : packageInfos) {
                if (packageName.equals(packageInfo.packageName)) {
                    install = true;
                    break;
                }
            }
        }
        return install;
    }

    /**
     * 获得App大小
     *
     * @param context
     * @return
     */
    public static long getAppSzie(Context context) {
        return getAppSzie(context, context.getPackageName());
    }

    /***
     * 获得App大小
     *
     * @param context
     * @param packageName
     * @return
     */
    public static long getAppSzie(Context context, String packageName) {
        long size = 0;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    if (packageInfo.applicationInfo != null) {
                        File appDir = new File(packageInfo.applicationInfo.publicSourceDir);
                        size = getAppSzie(appDir);
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return size;
    }

    /***
     * 获得App大小
     *
     * @param file
     * @return
     */
    public static long getAppSzie(File file) {
        long size = 0;
        if (file.exists() & file.isFile()) {
            size = file.length();
        }
        return size;
    }

    public static long getAppFirstInstallTime(Context context, String packageName) {
        long time = 0;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    time = packageInfo.firstInstallTime;
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return time;
    }

    public static long getApplastUpdateTime(Context context, String packageName) {
        long time = 0;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
                if (packageInfo != null) {
                    time = packageInfo.lastUpdateTime;
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
        return time;
    }


    /**
     * 获取签名SHA1
     *
     * @param context
     * @return
     */
    public static String getSHA1(Context context) {
        return getSHA1(context, context.getPackageName());
    }

    /**
     * 获取签名SHA1
     *
     * @param context     Context
     * @param packageName
     * @return
     */
    public static String getSHA1(Context context, String packageName) {
        // SHA1
        String sha1 = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                if (packageInfo != null) {
                    if ((packageInfo.signatures != null) && (packageInfo.signatures.length > 0)) {
                        byte[] cert = packageInfo.signatures[0].toByteArray();
                        // 将签名转换为字节数组流
                        InputStream input = new ByteArrayInputStream(cert);
                        // 证书工厂类，这个类实现了出厂合格证算法的功能
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
                        // X509证书，X.509是一种非常通用的证书格式
                        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(input);
                        // 加密算法的类，这里的参数可以使MD4,MD5等加密算法
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
                        // 获得公钥
                        byte[] publicKey = messageDigest.digest(x509Certificate.getEncoded());
                        sha1 = Bytes.toHexString(publicKey);
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return sha1;
    }

    /**
     * 获取签名SHA1
     *
     * @param context Context
     * @param file    文件
     * @return
     */
    public static String getSHA1(Context context, File file) {
        // SHA1
        String sha1 = "";
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_SIGNATURES);
            if (packageInfo != null) {
                if ((packageInfo.signatures != null) && (packageInfo.signatures.length > 0)) {
                    byte[] cert = packageInfo.signatures[0].toByteArray();
                    try {
                        // 将签名转换为字节数组流
                        InputStream input = new ByteArrayInputStream(cert);
                        // 证书工厂类，这个类实现了出厂合格证算法的功能
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
                        // X509证书，X.509是一种非常通用的证书格式
                        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(input);
                        // 加密算法的类，这里的参数可以使MD4,MD5等加密算法
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
                        // 获得公钥
                        byte[] publicKey = messageDigest.digest(x509Certificate.getEncoded());
                        sha1 = Bytes.toHexString(publicKey);
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return sha1;
    }

    /**
     * 获得Uid
     *
     * @param context
     * @return
     */
    public static int getUid(Context context) {
        int uid = 0;
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager != null) {
                ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), PackageManager.GET_ACTIVITIES);
                uid = applicationInfo.uid;
            }
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return uid;
    }

    /**
     * 是否前台
     *
     * @param context
     * @return
     */
    public static boolean isForeground(Context context) {
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> processes = manager.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo process : processes) {
            if (process.processName.equals(getPackageName(context))) {
                if (process.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
                    return true;
                } else {
                    return false;
                }
            }
        }
        return false;
    }
}
