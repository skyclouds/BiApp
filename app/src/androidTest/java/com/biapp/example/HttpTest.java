package com.biapp.example;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.BIApp;
import com.biapp.http.RetrofitClient;
import com.biapp.util.FileUtil;
import com.biapp.util.PrintfUtil;
import com.koushikdutta.async.http.AsyncHttpClient;
import com.koushikdutta.async.http.AsyncHttpGet;
import com.koushikdutta.async.http.server.AsyncHttpServer;
import com.koushikdutta.async.http.server.AsyncHttpServerRequest;
import com.koushikdutta.async.http.server.AsyncHttpServerResponse;
import com.koushikdutta.async.http.server.HttpServerRequestCallback;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

@RunWith(AndroidJUnit4.class)
public class HttpTest {

    @Test
    public void httpTest() throws Exception {
        new RetrofitClient("http://192.168.1.3:5000")
                .addHeader("Content-Type", "application/json")
                .post("test", "{}")
                .subscribe(response -> {

                }, throwable -> PrintfUtil.e(throwable));
        Thread.sleep(Long.MAX_VALUE);
    }

    @Test
    public void httpsTest() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
        kmf.init(ks, "storepass".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
        tmf.init(ts);
        new RetrofitClient("https://192.168.1.3:8888")
                .addHeader("Content-Type", "application/json")
                .initSSLContext(kmf, tmf)
                .post("test", "{}")
                .subscribe(response -> {

                }, throwable -> PrintfUtil.e(throwable));
        Thread.sleep(Long.MAX_VALUE);
    }

    @Test
    public void kldServerTest() throws Exception {
        Certificate cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(FileUtil.readAssetsFile(BIApp.getContext(), "KLD_SERVER_CA_D.crt"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, null);
        ts.setCertificateEntry("server", cert);
        tmf.init(ts);
        new RetrofitClient("https://192.168.1.178:9090")
                .initSSLContext(null, tmf)
                .post("checkServerVesion")
                .subscribe(response -> {

                }, throwable -> PrintfUtil.e(throwable));
        Thread.sleep(Long.MAX_VALUE);
    }

    @Test
    public void sslTest() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        ks.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
        kmf.init(ks, "storepass".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
        tmf.init(ts);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        AsyncHttpServer httpServer = new AsyncHttpServer();
        httpServer.listenSecure(8888, sslContext);
        httpServer.get("/", new HttpServerRequestCallback() {
            @Override
            public void onRequest(AsyncHttpServerRequest request, AsyncHttpServerResponse response) {
                response.send("hello");
            }
        });

        Thread.sleep(3000);

        AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setSSLContext(sslContext);
        AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setTrustManagers(tmf.getTrustManagers());
        AsyncHttpClient.getDefaultInstance().executeString(new AsyncHttpGet("https://localhost:8888/"), null).get();

        Thread.sleep(Long.MAX_VALUE);
    }

}
