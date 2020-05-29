package com.biapp.http;

/**
 * @author Yun
 */
public class HttpProgress {
    private String url;
    private String filePath;
    private long cur = 0;
    private long total = -1;
    private double percent = 0.00;

    public HttpProgress() {

    }

    public HttpProgress(long cur, long total, double percent) {
        this.cur = cur;
        this.total = total;
        this.percent = percent;
    }

    public long getCur() {
        return cur;
    }

    public void setCur(long cur) {
        this.cur = cur;
    }

    public long getTotal() {
        return total;
    }

    public void setTotal(long total) {
        this.total = total;
    }

    public double getPercent() {
        return percent;
    }

    public void setPercent(double percent) {
        this.percent = percent;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

}
