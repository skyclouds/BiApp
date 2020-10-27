package com.biapp.example;

import android.os.Bundle;
import android.widget.Button;
import android.widget.RadioGroup;
import android.widget.TextView;

import com.biapp.BIActivity;
import com.biapp.BIApp;
import com.biapp.http.HttpServer;
import com.biapp.http.HttpsServer;
import com.biapp.util.DeviceInfoUtil;
import com.biapp.util.FileUtil;
import com.koushikdutta.async.http.Multimap;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author yun
 */
public class HttpServerActivity extends BIActivity {

    private Button btn_start, btn_stop;
    private RadioGroup rp;
    private TextView tv_info;
    private boolean https;
    private MyHttpServer httpServer;
    private MyHttpsServer httpsServer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        httpServer = new MyHttpServer();
        httpsServer = new MyHttpsServer();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_http);
        rp = findViewById(R.id.rp);
        rp.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rbtn_https) {
                https = true;
            } else {
                https = false;
            }
        });
        btn_start = findViewById(R.id.btn_start);
        btn_start.setOnClickListener(v -> {
            if (https) {
                httpsServer.startListener(new String[]{"test"});
                tv_info.setText("start Https Server in " + DeviceInfoUtil.getIpAddress(this) + ":" + httpsServer.getPort());
            } else {
                httpServer.startListener(new String[]{"test"});
                tv_info.setText("start Http Server in " + DeviceInfoUtil.getIpAddress(this) + ":" + httpServer.getPort());
            }
        });
        btn_stop = findViewById(R.id.btn_stop);
        btn_stop.setOnClickListener(v -> {
            if (https) {
                httpsServer.stopListener();
            } else {
                httpServer.stopListener();
            }
            tv_info.setText("stop!");
        });
        tv_info = findViewById(R.id.tv_info);
    }

    private class MyHttpServer extends HttpServer {
        @Override
        protected void handlerRequest(String url, Map<String, String> headers, Map<String, String> query, String body) {
            httpServer.sendResponse("hello!");
        }
    }

    private class MyHttpsServer extends HttpsServer {
        @Override
        protected void handlerRequest(String url, Map<String, String> headers, Map<String, String> query, String body) {
            httpServer.sendResponse("hello!");
        }

        @Override
        protected SSLContext getSSLContext() {
            SSLContext sslContext = null;
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
                kmf.init(ks, "storepass".toCharArray());
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
                ts.load(FileUtil.readAssetsFile(BIApp.getContext(), "keystore.bks"), "storepass".toCharArray());
                tmf.init(ts);
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | KeyManagementException e) {
                e.printStackTrace();
            }
            return sslContext;
        }
    }

}
