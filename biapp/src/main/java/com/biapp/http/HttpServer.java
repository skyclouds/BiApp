package com.biapp.http;


import com.biapp.BIApp;
import com.biapp.lib.R;
import com.biapp.utils.GsonUtil;
import com.koushikdutta.async.AsyncNetworkSocket;
import com.koushikdutta.async.http.AsyncHttpPost;
import com.koushikdutta.async.http.Multimap;
import com.koushikdutta.async.http.server.AsyncHttpServer;
import com.koushikdutta.async.http.server.AsyncHttpServerRequest;
import com.koushikdutta.async.http.server.AsyncHttpServerResponse;
import com.koushikdutta.async.http.server.HttpServerRequestCallback;

import io.reactivex.disposables.Disposable;
import timber.log.Timber;

/**
 * HttpServer
 *
 * @author Yun
 */
public class HttpServer implements HttpServerRequestCallback {


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
        Timber.d("onCreate");
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
        Timber.d("【startListener】");
        this.interfaceNames = interfaceNames;
        if (!listener) {
            Timber.d("startListener");
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
        Timber.d("【stopListener】");
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
        Timber.i("【RemoteIP】%s", remoteIP);
        String url = request.getPath();
        Timber.d("【Url】%s", url);
        Multimap headers = request.getHeaders().getMultiMap();
        Timber.d("【Header】%s", GsonUtil.toJson(headers));
        String method = request.getMethod();
        Timber.d("【Method】%s", method);
        String Content_Type = request.getHeaders().get("Content-Type");
        Timber.d("【Content-Type】%s", Content_Type);
        String requestData = null;
        if (method.equals(AsyncHttpPost.METHOD)) {
            //获取post请求的参数
            if (request.getBody() != null && request.getBody().get() != null) {
                requestData = request.getBody().get().toString();
            }
        }
        Timber.d("【RequestData】%s", requestData);
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
        Timber.d("【Response】%s", responseData);
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
