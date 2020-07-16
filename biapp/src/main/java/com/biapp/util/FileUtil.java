package com.biapp.util;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Environment;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import aura.data.Strings;

/**
 * @author Yun
 */
public class FileUtil {


    public final static String USB_PATH = "/storage/usbotg";

    /**
     * 判断是否挂载
     *
     * @param path
     * @return
     */
    public static boolean isMounted(String path) {
        boolean mount = false;
        String record = null;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/mounts"));
            while ((record = reader.readLine()) != null) {
                if (record.contains(path)) {
                    mount = true;
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                    reader = null;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return mount;
    }

    /**
     * 获得文件大小
     *
     * @param file
     * @return
     */
    public static long getSize(File file) {
        long size = 0;
        if (!file.exists()) {
            return size;
        } else {
            if (file.isFile()) {
                size = file.length();
            }
            if (file.isDirectory()) {
                File[] files = file.listFiles();
                for (File tmpFile : files) {
                    size += getSize(tmpFile);
                }
            }
        }
        return size;
    }

    /****
     * 重命名文件
     *
     * @param srcFile
     *            原文件
     * @param objFile
     *            目标文件
     */
    public static boolean rename(File srcFile, File objFile) {
        boolean rename = false;
        if (srcFile.exists()) {
            if (!objFile.getParentFile().exists()) {
                objFile.getParentFile().mkdirs();
            }
            rename = srcFile.renameTo(objFile);
        }
        return rename;
    }

    /***
     * Read File
     * @param file
     * @return
     * @throws FileNotFoundException
     */
    public static InputStream read(File file) {
        InputStream inputStream = null;
        if (file.exists()) {
            try {
                inputStream = new FileInputStream(file);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        return inputStream;
    }

    /**
     * 转为字节
     *
     * @param input
     * @return
     */
    public static byte[] toByteArray(InputStream input) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read = 0;
            while (-1 != (read = input.read(buffer))) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /***
     * 读取字符串
     *
     * @param inputStream
     * @param encode
     * @return
     */
    public static String readString(InputStream inputStream, String encode) {
        String read = "";
        try {
            if (inputStream != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, encode));
                StringBuilder buffer = new StringBuilder();
                String line = null;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    if (lineNum > 0) {
                        buffer.append(System.lineSeparator());
                    }
                    buffer.append(line);
                    lineNum++;
                }
                read = buffer.toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return read;
    }

    /**
     * 读取配置文件
     *
     * @param inputStream
     * @return
     */
    public static Map<String, String> readProperties(InputStream inputStream) {
        Map<String, String> map = new HashMap<String, String>();
        try {
            // 加载文件
            Properties properties = new Properties();
            properties.load(inputStream);
            // 获得数据
            Iterator<Map.Entry<Object, Object>> iterator = properties.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<Object, Object> entry = iterator.next();
                Object key = entry.getKey();
                Object value = entry.getValue();
                map.put(String.valueOf(key), String.valueOf(value));
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return map;
    }

    /**
     * 读取Ini
     *
     * @param inputStream
     * @return
     */
    public static Map<String, Map<String, String>> readIni(InputStream inputStream) {
        Map<String, Map<String, String>> config = new HashMap<>();
        Map<String, String> params = new HashMap<>();
        BufferedReader bufferedReader = null;
        InputStreamReader inputStreamReader = null;
        try {
            inputStreamReader = new InputStreamReader(inputStream);
            bufferedReader = new BufferedReader(inputStreamReader);
            String line;
            String sectionName = "global";
            while ((line = bufferedReader.readLine()) != null) {
                //去除注释
                line = FormatUtil.removeIniComments(line);
                //空行
                if (Strings.isNullOrEmpty(line)) {
                    continue;
                } else {
                    //section
                    if (line.startsWith("[") && line.endsWith("]")) {
                        sectionName = line.substring(1, line.length() - 1).trim();
                        params = config.get(sectionName);
                        if (params == null) {
                            params = new HashMap<>();
                        }
                    }
                    //params
                    else if (line.matches(".*=.*")) {
                        String name = line.substring(0, line.indexOf('=')).trim();
                        String value = line.substring(line.indexOf('=') + 1).trim();
                        params.put(name, value);
                        config.put(sectionName, params);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
                if (inputStreamReader != null) {
                    inputStreamReader.close();
                }
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return config;
    }

    /****
     * 保存图片
     *
     * @param bitmap
     * @param saveFile
     * @return
     */
    public static boolean saveFile(Bitmap bitmap, File saveFile) {
        boolean save = false;
        try {
            if (saveFile.exists()) {
                saveFile.delete();
            }
            saveFile.createNewFile();
            BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream(saveFile));
            bitmap.compress(Bitmap.CompressFormat.JPEG, 100, output);
            output.flush();
            output.close();
            save = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return save;
    }

    /**
     * 保存
     *
     * @param saveFile
     * @param data
     * @return
     */
    public static boolean save(File saveFile, String data) {
        boolean save = false;
        try {
            if (saveFile.exists()) {
                delete(saveFile);
            }
            saveFile.getParentFile().mkdirs();
            saveFile.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(saveFile);
            fileOutputStream.write(data.getBytes());
            fileOutputStream.flush();
            fileOutputStream.close();
            save = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return save;
    }

    public static boolean saveLog(File logFile, String log) {
        boolean save = false;
        try {
            FileWriter fileWriter = new FileWriter(logFile, true);
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.println(log);
            printWriter.flush();
            fileWriter.flush();
            fileWriter.close();
            fileWriter.close();
            save = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return save;
    }


    /**
     * 压缩文件
     *
     * @param srcFiles
     * @param zipFile
     * @return
     */
    public static boolean zipFiles(File[] srcFiles, File zipFile) {
        boolean zip = false;
        try {
            FileOutputStream fileOutput = new FileOutputStream(zipFile);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(fileOutput);
            ZipOutputStream zipOutput = new ZipOutputStream(bufferedOutput);
            for (int i = 0; i < srcFiles.length; i++) {
                // 实例化 ZipEntry 对象，源文件数组中的当前文件
                ZipEntry zipEntry = new ZipEntry(srcFiles[i].getName());
                // 将源文件数组中的当前文件读入 FileInputStream 流中
                FileInputStream fileInput = new FileInputStream(srcFiles[i]);
                zipOutput.putNextEntry(zipEntry);
                int len;
                // 定义每次读取的字节数组
                byte[] buffer = new byte[1024];
                while ((len = fileInput.read(buffer)) != -1) {
                    zipOutput.write(buffer, 0, len);
                }
                fileInput.close();
                zipOutput.closeEntry();
            }
            zipOutput.finish();
            zipOutput.close();
            zip = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return zip;
    }

    /**
     * 复制文件
     *
     * @param target 源文件
     * @param target 复制到的新文件
     */
    public static boolean copyFile(File src, File target) {
        boolean copy = false;
        FileInputStream fi = null;
        FileOutputStream fo = null;
        FileChannel in = null;
        FileChannel out = null;
        try {
            fi = new FileInputStream(src);
            fo = new FileOutputStream(target);
            // 得到对应的文件通道
            in = fi.getChannel();
            // 得到对应的文件通道
            out = fo.getChannel();
            // 连接两个通道，并且从in通道读取，然后写入out通道
            in.transferTo(0, in.size(), out);
            copy = true;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                fi.close();
                in.close();
                fo.close();
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return copy;
    }


    /***
     * 删除文件
     *
     * @param file
     */
    public static void delete(File file) {
        if (file.exists()) {
            if (file.isDirectory()) {
                File[] files = file.listFiles();
                for (File tmpFile : files) {
                    delete(tmpFile);
                }
            }
            file.delete();
        }
    }


    /***
     * 分割文件
     *
     * @param fileInputStream
     *            文件
     * @param splitSize
     *            分割大小
     * @param outDirPath
     *            输出目录
     *
     */
    public static List<File> splitFile(InputStream fileInputStream, long splitSize, String outDirPath) {
        List<File> split = new ArrayList<File>();
        try {
            int num = 0;
            byte[] buff = new byte[1024];
            File outDir = new File(outDirPath);
            if (!outDir.exists()) {
                outDir.mkdirs();
            }
            while (true) {
                File splitFile = new File(outDirPath + "/" + getProguardName(num) + ".data");
                split.add(splitFile);
                FileOutputStream fileOutputStream = new FileOutputStream(splitFile);
                for (int i = 0; i < splitSize / buff.length; i++) {
                    int read = fileInputStream.read(buff);
                    fileOutputStream.write(buff, 0, read);
                    // 判断大文件读取是否结束
                    if (read < buff.length) {
                        fileInputStream.close();
                        fileOutputStream.close();
                        return split;
                    }
                }
                fileOutputStream.close();
                num++;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return split;
    }

    /***
     * 分割文件
     *
     * @param srcFile
     *            源文件
     * @param splitSize
     *            分割大小
     * @param outDirPath
     *            输出目录
     *
     */
    public static List<File> splitFile(File srcFile, long splitSize, String outDirPath) {
        if (srcFile.exists() && srcFile.isFile()) {
            try {
                FileInputStream fileInputStream = new FileInputStream(srcFile);
                return splitFile(fileInputStream, splitSize, outDirPath);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /****
     * 联合文件
     *
     * @param splitInputStream
     * @param outFile
     * @return
     */
    public static boolean combineFileInputStream(List<InputStream> splitInputStream, File outFile) {
        boolean combine = true;
        if (outFile.exists()) {
            outFile.delete();
        }
        try {
            OutputStream outputStream = new FileOutputStream(outFile);
            byte[] buffer = new byte[1024];
            int readLen = 0;
            for (int i = 0; i < splitInputStream.size(); i++) {
                while ((readLen = splitInputStream.get(i).read(buffer)) != -1) {
                    outputStream.write(buffer, 0, readLen);
                }
                outputStream.flush();
                splitInputStream.get(i).close();
            }
            // 把所有小文件都进行写操作后才关闭输出流，这样就会合并为一个文件了
            outputStream.close();
            combine = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return combine;
    }

    /****
     * 联合文件
     *
     * @param splitFile
     * @param outFile
     * @return
     */
    public static boolean combineFile(List<File> splitFile, File outFile) {
        List<InputStream> splitFileInputStream = new ArrayList<InputStream>();
        try {
            for (int i = 0; i < splitFile.size(); i++) {
                splitFileInputStream.add(new FileInputStream(splitFile.get(i)));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return combineFileInputStream(splitFileInputStream, outFile);
    }

    /***
     * 获得混淆名字
     *
     * @param num
     * @return
     */
    public static String getProguardName(int num) {
        char[] proguard = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z'};
        StringBuffer name = new StringBuffer();
        if (num < 0) {
            name.append("_");
            num = Math.abs(num);
        }
        if (num == 0) {
            name.append("0");
        }
        if (num > 0) {
            // 获得位权
            List<Integer> bit = new ArrayList<Integer>();
            do {
                // 余数
                int yushu = num - (num / (proguard.length + 1)) * (proguard.length + 1);
                // 商
                num = num / (proguard.length + 1);
                bit.add(yushu);
            } while (num > 0);
            for (int i = 0; i < bit.size(); i++) {
                int bitValue = bit.get(bit.size() - 1 - i);
                if (bitValue == 0) {
                    name.append('0');
                } else {
                    name.append(proguard[bitValue - 1]);
                }
            }
        }
        return name.toString();
    }


    /***
     * 保存文件
     *
     * @param inputStream
     * @param saveFile
     */
    public static boolean saveFile(InputStream inputStream, File saveFile) {
        boolean save = false;
        try {
            //创建目录
            if (!saveFile.getParentFile().exists()) {
                saveFile.getParentFile().mkdirs();
            }
            //删除旧文件
            if (saveFile.exists()) {
                saveFile.delete();
            }
            saveFile.createNewFile();
            // 写入文件
            FileOutputStream output = new FileOutputStream(saveFile);
            int read = 0;
            byte[] buffer = new byte[1024];
            while ((read = inputStream.read(buffer)) != -1) {
                output.write(buffer, 0, read);
                output.getFD().sync();
            }
            output.flush();
            output.close();
            save = true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return save;
    }


    /**
     * 获得SD卡路径
     *
     * @return
     */
    public static String getSDCradPath() {
        return Environment.getExternalStorageDirectory() + "/";
    }

    /***
     * 获得App路径
     *
     * @param context
     * @return
     */
    public static String getAppPath(Context context) {
        return context.getFilesDir().getParentFile().getAbsolutePath() + "/";
    }


    /***
     * 获得App文件路径
     *
     * @param context
     * @return
     */
    public static String getAppFilePath(Context context) {
        return context.getFilesDir().getAbsolutePath() + "/";
    }

    /***
     * 获得App缓存路径
     *
     * @param context
     * @return
     */
    public static String getAppCache(Context context) {
        return context.getCacheDir() + "/";
    }


    /***
     * 是否是Apk文件
     *
     * @param context
     * @param file
     * @return
     */
    public static boolean isApkFile(Context context, File file) {
        boolean apk = false;
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            PackageInfo packageInfo = packageManager.getPackageArchiveInfo(file.getAbsolutePath(), PackageManager.GET_ACTIVITIES);
            if (packageInfo != null) {
                apk = true;
            }
        }
        return apk;
    }

    /****
     * 获得Assets的Uri
     *
     * @param filePath
     * @return
     */
    public static Uri getAssetsUri(String filePath) {
        Uri uri = Uri.parse("file:///android_asset/" + filePath);
        return uri;
    }


    /***
     * 文件授权
     * @param powerCode 权限编码 例如777
     * @param file
     * @return
     */
    public static int grantPower(String powerCode, File file) {
        int status = 0;
        try {
            Process process = Runtime.getRuntime().exec("chmod " + powerCode + " " + file);
            status = process.waitFor();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return status;
    }


    /***
     * 读取Raw文件
     *
     * @param context
     * @param rawId
     * @return
     */
    public static InputStream readRawFile(Context context, int rawId) {
        return context.getResources().openRawResource(rawId);
    }

    /***
     * 读取Assets文件
     *
     * @param context
     * @param filePath
     * @return
     */
    public static InputStream readAssetsFile(Context context, String filePath) {
        try {
            return context.getAssets().open(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
