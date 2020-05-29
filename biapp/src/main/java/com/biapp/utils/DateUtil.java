package com.biapp.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * @author Yun
 */
public class DateUtil {

    /**
     * 秒
     */
    public static final long SECOND = 1000;
    /**
     * 分
     */
    public static final long MINUTE = SECOND * 60;
    /**
     * 小时
     */
    public static final long HOUR = MINUTE * 60;
    /**
     * 天
     */
    public static final long DAY = HOUR * 24;

    /***
     * 格式化时间字符串
     *
     * @param time
     * @return
     */
    public static Date getData(long time) {
        Date date = null;
        date = new Date(time);
        return date;
    }

    /***
     * 格式化时间字符串
     *
     * @param pattern
     * @param timeString
     * @return
     */
    public static Date getData(String pattern, String timeString) {
        Date date = null;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(pattern);
            date = sdf.parse(timeString);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return date;
    }

    /**
     * 获得日期
     *
     * @param pattern
     * @param timeString
     * @return
     */
    public static Calendar getCalendar(String pattern, String timeString) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(getData(pattern, timeString));
        return cal;
    }


    /***
     * 格式化时间字符串
     *
     * @param date
     * @return
     */
    public static String formatTimeString(Date date) {
        String format = "";
        SimpleDateFormat sdf = null;
        Date today = new Date();
        // 当天时间内
        if (0 >= daysBetween(today, date)) {
            sdf = new SimpleDateFormat("HH:mm");
            format = sdf.format(date);
        }
        // 一周内
        else if (daysBetween(today, date) > 0 && daysBetween(today, date) <= 7) {
            sdf = new SimpleDateFormat("E");
            format = sdf.format(date);
        }
        // 一年内
        else if (daysBetween(today, date) > 7 && daysBetween(today, date) <= 365) {
            sdf = new SimpleDateFormat("MM月dd日");
            format = sdf.format(date);
        }
        // 超过一年
        else if (daysBetween(today, date) > 365) {
            sdf = new SimpleDateFormat("yyyy年MM月dd日");
            format = sdf.format(date);
        }
        return format;
    }

    /***
     * 获得时间字符串
     *
     * @param pattern
     * @param millSec
     * @return
     */
    public static String getDateString(String pattern, long millSec) {
        SimpleDateFormat sdf = new SimpleDateFormat(pattern);
        Date date = new Date(millSec);
        return sdf.format(date);
    }

    /**
     * 计算两个日期之间的天数
     *
     * @param startDate 开始
     * @param endDate   结束
     * @return
     */
    public static long daysBetween(Date startDate, Date endDate) {
        long betweenDays = 0;
        long startTime = startDate.getTime();
        long endTime = endDate.getTime();
        long betweenTime = Math.abs(endTime - startTime);
        betweenDays = betweenTime / DAY;
        return betweenDays;
    }

    /**
     * 获取当天日期
     *
     * @param pattern
     * @return
     */
    public static String getCurrentDate(String pattern) {
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(System.currentTimeMillis());
    }

    /**
     * 获取昨天的日期
     *
     * @param pattern
     * @return
     */
    public static String getYesterday(String pattern) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取N天前的日期
     *
     * @param pattern
     * @param many
     * @return
     */
    public static String getManyDaysAgo(String pattern, int many) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -many);
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取当月
     *
     * @param pattern
     * @return
     */
    public static String getCurrentMonth(String pattern) {
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(System.currentTimeMillis());
    }

    /**
     * 获取上月
     *
     * @param pattern
     * @return
     */
    public static String getLastMonth(String pattern) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -1);
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取本月第一天
     *
     * @param pattern
     * @return
     */
    public static String getFirstDayOfMonth(String pattern) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.DATE, 1);
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取本周星期一
     *
     * @param pattern
     * @return
     */
    public static String getMondayOfWeek(String pattern) {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        calendar.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取上月第一天
     *
     * @param pattern
     * @return
     */
    public static String getFirstDayOfLastMonth(String pattern) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -1);
        calendar.set(Calendar.DATE, 1);
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }

    /**
     * 获取上月最后一天
     *
     * @param pattern
     * @return
     */
    public static String getLastDayOfLastMonth(String pattern) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -1);
        calendar.roll(Calendar.DATE, -1);
        calendar.set(Calendar.DATE, calendar.getActualMaximum(Calendar.DAY_OF_MONTH));
        SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
        return dateFormat.format(calendar.getTime());
    }
}
