package com.biapp.http;


import com.biapp.BIApp;
import com.biapp.lib.R;
import com.biapp.util.GsonUtil;
import com.biapp.util.PrintfUtil;
import com.koushikdutta.async.AsyncNetworkSocket;
import com.koushikdutta.async.http.AsyncHttpPost;
import com.koushikdutta.async.http.Multimap;
import com.koushikdutta.async.http.server.AsyncHttpServer;
import com.koushikdutta.async.http.server.AsyncHttpServerRequest;
import com.koushikdutta.async.http.server.AsyncHttpServerResponse;
import com.koushikdutta.async.http.server.HttpServerRequestCallback;

import io.reactivex.disposables.Disposable;


/**
 * HttpServer
 *
 * @author Yun
 */
public class HttpServer implements HttpServerRequestCallback {

    private final String TAG = this.getClass().getSimpleName();

    /**
     * 默认实例
     */
    private static HttpServer instance;

    /***
     * HTTP服务
     */
    private AsyncHttpServer httpServer;
    /**
     * 端口
     */
    private int port = 5000;

    /**
     * 响应
     */
    private AsyncHttpServerResponse response;

    private boolean listener;

    private String[] interfaceNames;

    private Disposable workDisposable;


    public static HttpServer getInstance() {
        if (instance == null) {
            instance = new HttpServer();
        }
        return instance;
    }

    private HttpServer() {
        PrintfUtil.d(TAG, "onCreate");
        init();
    }


    /**
     * 初始化
     */
    private void init() {
        httpServer = new AsyncHttpServer();
    }

    public boolean isListener() {
        return listener;
    }


    /**
     * 开始监听
     */
    public void startListener(String[] interfaceNames) {
        PrintfUtil.d(TAG, "startListener");
        this.interfaceNames = interfaceNames;
        if (!listener) {
            PrintfUtil.d(TAG, "startListener");
            httpServer.get("[\\d\\D]*", this);
            httpServer.post("[\\d\\D]*", this);
            httpServer.listen(port);
            listener = true;
        }
    }

    /**
     * 停止监听
     */
    public void stopListener() {
        PrintfUtil.d(TAG, "stopListener");
        if (listener) {
            if (this.response != null) {
                this.response.getSocket().close();
            }
            httpServer.stop();
            listener = false;
            //停止工作
            if (workDisposable != null) {
                if (!workDisposable.isDisposed()) {
                    workDisposable.dispose();
                }
                workDisposable = null;
            }
        }
    }

    @Override
    public void onRequest(AsyncHttpServerRequest request, AsyncHttpServerResponse response) {
        this.response = response;
        String remoteIP = ((AsyncNetworkSocket) request.getSocket()).getRemoteAddress().getAddress().getHostAddress();
        PrintfUtil.i("RemoteIP", remoteIP);
        String url = request.getPath();
        PrintfUtil.d("Url", url);
        Multimap headers = request.getHeaders().getMultiMap();
        PrintfUtil.d("Header", GsonUtil.toJson(headers));
        String method = request.getMethod();
        PrintfUtil.d("Method", method);
        String Content_Type = request.getHeaders().get("Content-Type");
        PrintfUtil.d("Content-Type", Content_Type);
        String requestData = null;
        if (method.equals(AsyncHttpPost.METHOD)) {
            //获取post请求的参数
            if (request.getBody() != null && request.getBody().get() != null) {
                requestData = request.getBody().get().toString();
            }
        }
        PrintfUtil.d("RequestData", requestData);
        //是否在监听
        if (isInListenerInterface(url)) {
            switch (url) {
                default:
                    break;
            }
        } else {
            sendResponse(BIApp.getContext().getString(R.string.server_not_found));
        }
    }

    /**
     * 发送响应
     *
     * @param responseData
     */
    private void sendResponse(String responseData) {
        PrintfUtil.d("Response", responseData);
        response.send(responseData);
    }

    /**
     * 是否在监听的接口中
     *
     * @param url
     * @return
     */
    private boolean isInListenerInterface(String url) {
        boolean in = false;
        for (String interfaceName : interfaceNames) {
            if (url.equals(interfaceName)) {
                in = true;
                break;
            }
        }
        return in;
    }
}
