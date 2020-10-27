package com.biapp.http;


import com.biapp.BIApp;
import com.biapp.lib.R;
import com.biapp.util.FileUtil;
import com.biapp.util.GsonUtil;
import com.biapp.util.PrintfUtil;
import com.koushikdutta.async.AsyncNetworkSocket;
import com.koushikdutta.async.http.server.AsyncHttpServerRequest;
import com.koushikdutta.async.http.server.AsyncHttpServerResponse;
import com.koushikdutta.async.http.server.HttpServerRequestCallback;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import io.reactivex.disposables.Disposable;


/**
 * HttpsServer
 *
 * @author Yun
 */
public abstract class HttpsServer implements HttpServerRequestCallback {

    private final String TAG = this.getClass().getSimpleName();

    /***
     * HTTPS服务
     */
    private SSLAsyncHttpServer httpsServer;
    /**
     * 端口
     */
    private int port = 8888;

    /**
     * 响应
     */
    private AsyncHttpServerResponse response;

    private boolean listener;

    private String[] interfaceNames;

    private Disposable workDisposable;

    public HttpsServer() {
        init(port);
    }

    public HttpsServer(int port) {
        init(port);
    }

    /**
     * 初始化
     */
    private void init(int port) {
        PrintfUtil.d(TAG, "onCreate");
        this.port = port;
        httpsServer = new SSLAsyncHttpServer();
    }

    public boolean isListener() {
        return listener;
    }

    public int getPort() {
        return port;
    }

    /**
     * 开始监听
     */
    public void startListener(String[] interfaceNames) {
        PrintfUtil.d(TAG, "startListener");
        this.interfaceNames = interfaceNames;
        if (!listener) {
            PrintfUtil.d(TAG, "startListener");
            httpsServer.get("[\\d\\D]*", this);
            httpsServer.post("[\\d\\D]*", this);
            httpsServer.listenSecure(port, getSSLContext());
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
            httpsServer.stop();
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
        String url = request.getPath().substring(1);
        PrintfUtil.d("Url", url);
        Map<String, String> headers = new HashMap<>();
        if (request.getHeaders() != null && request.getHeaders().getMultiMap() != null && request.getHeaders().getMultiMap().size() > 0) {
            headers = request.getHeaders().getMultiMap().toSingleMap();
            PrintfUtil.d("Headers", GsonUtil.toJson(headers));
        }
        String method = request.getMethod();
        PrintfUtil.d("Method", method);
        Map<String, String> query = new HashMap<>();
        if (request.getQuery() != null) {
            query = request.getQuery().toSingleMap();
            PrintfUtil.d("Query", GsonUtil.toJson(query));
        }
        String body = null;
        if (request.getBody() != null && request.getBody().get() != null) {
            body = request.getBody().get().toString();
            PrintfUtil.d("Body", body);
        }
        //是否在监听
        if (isInListenerInterface(url)) {
            switch (url) {
                default:
                    handlerRequest(url, headers, query, body);
                    break;
            }
        } else {
            sendResponse(BIApp.getContext().getString(R.string.server_not_found));
        }
    }

    /**
     * 处理请求
     *
     * @param url
     * @param headers
     * @param query
     * @param body
     */
    protected abstract void handlerRequest(String url, Map<String, String> headers, Map<String, String> query, String body);

    /**
     * 发送响应
     *
     * @param responseData
     */
    public void sendResponse(String responseData) {
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

    /**
     * 获得SSLContext
     *
     * @return
     */
    protected abstract SSLContext getSSLContext();
}
