package com.biapp.http;

import com.koushikdutta.async.AsyncSSLSocket;
import com.koushikdutta.async.AsyncSSLSocketWrapper;
import com.koushikdutta.async.AsyncServer;
import com.koushikdutta.async.AsyncServerSocket;
import com.koushikdutta.async.AsyncSocket;
import com.koushikdutta.async.callback.ListenCallback;
import com.koushikdutta.async.http.server.AsyncHttpServer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

/**
 * 支持双向认证的HTTP服务
 * @author yun
 */
public class SSLAsyncHttpServer extends AsyncHttpServer {

    private final String TAG = this.getClass().getSimpleName();

    private SSLEngine mSSLEngine;

    @Override
    public void listenSecure(final int port, final SSLContext sslContext) {
        AsyncServer.getDefault().listen(null, port, new ListenCallback() {
            @Override
            public void onAccepted(AsyncSocket socket) {
                mSSLEngine = sslContext.createSSLEngine();
                mSSLEngine.setNeedClientAuth(true);
                AsyncSSLSocketWrapper.handshake(socket, null, port, mSSLEngine, null, null, false,
                        new AsyncSSLSocketWrapper.HandshakeCallback() {
                            @Override
                            public void onHandshakeCompleted(Exception e, AsyncSSLSocket socket) {
                                if (socket != null) {
                                    getListenCallback().onAccepted(socket);
                                }
                            }
                        });
            }

            @Override
            public void onListening(AsyncServerSocket socket) {
                getListenCallback().onListening(socket);
            }

            @Override
            public void onCompleted(Exception ex) {
                getListenCallback().onCompleted(ex);
            }
        });
    }
}
