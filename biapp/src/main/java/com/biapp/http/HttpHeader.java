package com.biapp.http;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/**
 * @author Yun
 * @date 2017/12/6
 */
public class HttpHeader implements Interceptor {
    // 头部
    private Map<String, String> headers = null;


    /***
     * 构造函数
     *
     * @param headers Http头部信息
     */
    public HttpHeader(Map<String, String> headers) {
        if (headers != null) {
            this.headers = headers;
        }
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request.Builder builder = chain.request().newBuilder();
        if (!headers.isEmpty()) {
            Set<String> keys = headers.keySet();
            for (String headerKey : keys) {
                builder.addHeader(headerKey, headers.get(headerKey)).build();
            }
        }
        return chain.proceed(builder.build());
    }

    public Map<String, String> getHeaders() {
        return headers;
    }
}
