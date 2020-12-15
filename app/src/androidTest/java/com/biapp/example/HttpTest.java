package com.biapp.example;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.BIApp;
import com.biapp.http.RetrofitClient;
import com.biapp.util.FileUtil;
import com.biapp.util.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

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

}
