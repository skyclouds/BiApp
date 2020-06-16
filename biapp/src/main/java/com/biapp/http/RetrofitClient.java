package com.biapp.http;


import android.util.Base64;

import com.biapp.BIApp;
import com.biapp.BIAppException;
import com.biapp.utils.FormatUtil;
import com.biapp.utils.GsonUtil;
import com.biapp.utils.PrintfUtil;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.reactivex.Observable;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Single;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;
import okhttp3.Cache;
import okhttp3.ConnectionPool;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.internal.platform.Platform;
import retrofit2.HttpException;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import retrofit2.converter.gson.GsonConverterFactory;
import timber.log.Timber;

import com.biapp.lib.R;

/**
 * @author Yun
 * @date 2017/12/6
 */
public class RetrofitClient {

    private String host;
    private HttpHeader header;
    private SSLSocketFactory sslSocketFactory;
    private X509TrustManager trustManager;
    private OkHttpClient.Builder okHttpClientBuilder;
    private OkHttpClient okHttpClient;
    private retrofit2.Retrofit.Builder retrofitBuilder;
    private retrofit2.Retrofit retrofit;
    private boolean mutualAuth = false;
    private String sslProtocol = "TLSv1.2";
    private String contextType = "application/json";
    private CertificateFactory certificateFactory;
    private int connectTimeout = 15;
    private int writeTimeout = 15;
    private File cacheDir;
    private long cacheSize = FormatUtil.MB * 10;
    private Map<Long, Disposable> downloadMap = new HashMap<>();

    public static String UNKNOWN_HOST_EXCEPTION = BIApp.getContext().getString(R.string.unknown_host_exception);
    public static String PROTOCOL_EXCEPTION = BIApp.getContext().getString(R.string.protocol_exception);
    public static String CONNECT_EXCEPTION = BIApp.getContext().getString(R.string.connect_exception);
    public static String TIMEOUT_EXCEPTION = BIApp.getContext().getString(R.string.timeout_exception);
    public static String SSL_EXCEPTION = BIApp.getContext().getString(R.string.sll_exception);
    public static String CERT_EXCEPTION = BIApp.getContext().getString(R.string.cert_exception);
    public static String CERT_ALG_EXCEPTION = BIApp.getContext().getString(R.string.cert_alg_exception);
    public static String HTTP_EXCEPTION = BIApp.getContext().getString(R.string.http_exception);

    public RetrofitClient() {
        this.header = new HttpHeader(new HashMap<>());
    }

    public RetrofitClient(String host) {
        this.host = host;
        this.header = new HttpHeader(new HashMap<>());
    }

    public RetrofitClient setHost(String host) {
        this.host = host;
        return this;
    }

    public String getHost() {
        return host;
    }

    public RetrofitClient setTimeout(int timeout) {
        this.connectTimeout = timeout;
        this.writeTimeout = timeout;
        return this;
    }

    public RetrofitClient setCacheSize(long cacheSize) {
        this.cacheSize = cacheSize;
        return this;
    }

    public RetrofitClient setCacheDir(File cacheDir) {
        this.cacheDir = cacheDir;
        return this;
    }

    public RetrofitClient addHeader(String key, String value) {
        this.header.getHeaders().put(key, value);
        return this;
    }

    public RetrofitClient setHttpsCert(InputStream serverPubilcKeyCertInputStream) {
        return setHttpsCert(serverPubilcKeyCertInputStream, null);
    }

    public RetrofitClient setHttpsCert(InputStream serverPubilcKeyCertInputStream, String serverPubilcKeyCertPwd) {
        this.sslSocketFactory = getSSLSocketFactory(serverPubilcKeyCertInputStream, serverPubilcKeyCertPwd, null, null);
        return this;
    }

    public RetrofitClient setHttpsCert(InputStream serverPubilcKeyCertInputStream, InputStream clientPrivateKeyFileInputStream, InputStream caCertInputStream) {
        this.sslSocketFactory = getSSLSocketFactory(serverPubilcKeyCertInputStream, null, clientPrivateKeyFileInputStream, caCertInputStream);
        return this;
    }

    public RetrofitClient setHttpsCert(InputStream serverPubilcKeyCertInputStream, String serverPubilcKeyCertPwd, InputStream clientPrivateKeyFileInputStream, InputStream caCertInputStream) {
        this.sslSocketFactory = getSSLSocketFactory(serverPubilcKeyCertInputStream, serverPubilcKeyCertPwd, clientPrivateKeyFileInputStream, caCertInputStream);
        return this;
    }

    public RetrofitClient setCertificateFactory(CertificateFactory certificateFactory) {
        this.certificateFactory = certificateFactory;
        return this;
    }

    public RetrofitClient setMutualAuth(boolean mutualAuth) {
        this.mutualAuth = mutualAuth;
        return this;
    }

    public RetrofitClient setSSLProtocol(String sslProtocol) {
        this.sslProtocol = sslProtocol;
        return this;
    }

    public RetrofitClient setContextType(String contextType) {
        this.contextType = contextType;
        return this;
    }

    public <T> T buildService(Class<T> service) {
        return buildService(null, null, service);
    }

    public <T> T buildService(OkHttpClient.Builder okHttpClientBuilder, retrofit2.Retrofit.Builder retrofitBuilder, Class<T> service) {
        if (okHttpClientBuilder != null) {
            this.okHttpClientBuilder = okHttpClientBuilder;
        } else {
            this.okHttpClientBuilder = getDefaultOkHttpClientBuilder();
        }
        if (retrofitBuilder != null) {
            this.retrofitBuilder = retrofitBuilder;
        } else {
            this.retrofitBuilder = getDefaultRetrofitBuilder();
        }
        this.okHttpClient = this.okHttpClientBuilder.build();
        this.retrofitBuilder.client(this.okHttpClient);
        this.retrofit = this.retrofitBuilder.build();
        return this.retrofit.create(service);
    }

    private retrofit2.Retrofit.Builder getDefaultRetrofitBuilder() {
        retrofitBuilder = new retrofit2.Retrofit.Builder();
        retrofitBuilder.addConverterFactory(GsonConverterFactory.create());
        retrofitBuilder.addCallAdapterFactory(RxJava2CallAdapterFactory.create());
        retrofitBuilder.baseUrl(host);
        return retrofitBuilder;
    }


    private OkHttpClient.Builder getDefaultOkHttpClientBuilder() {
        okHttpClientBuilder = new OkHttpClient.Builder();
        //创建缓存文件目录
        if (cacheDir != null) {
            if (!cacheDir.exists()) {
                cacheDir.mkdirs();
            }
            // 设置缓存
            okHttpClientBuilder.cache(new Cache(cacheDir, cacheSize));
        }
        // 设置超时
        okHttpClientBuilder.connectTimeout(connectTimeout, TimeUnit.SECONDS);
        okHttpClientBuilder.writeTimeout(writeTimeout, TimeUnit.SECONDS);
        //设置HTTPS协议
        if (this.sslSocketFactory != null) {
            okHttpClientBuilder.sslSocketFactory(sslSocketFactory,trustManager);
        }
        //设置头部
        if (this.header != null && !this.header.getHeaders().isEmpty()) {
            Timber.d("【Header】" + GsonUtil.toJson(header.getHeaders()));
            okHttpClientBuilder.addInterceptor(header);
        }
        // 设置同时连接的个数和时间，默认5个，和每个保持时间为10s
        okHttpClientBuilder.connectionPool(new ConnectionPool(5, 10, TimeUnit.SECONDS));
        return okHttpClientBuilder;
    }


    private SSLSocketFactory getSSLSocketFactory(InputStream serverPubilcKeyCertInputStream, String serverPubilcKeyCertPwd, InputStream clientPrivateKeyFileInputStream, InputStream caCertInputStream) {
        try {
            SSLContext sslContext = SSLContext.getInstance(sslProtocol);
            if (mutualAuth) {
                Certificate caCert = certificateFactory.generateCertificate(caCertInputStream);
                KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null, null);
                trustStore.setCertificateEntry("ca", caCert);
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                trustManager = (X509TrustManager) trustManagers[0];

                TrustManager[] wrappedTrustManagers = new TrustManager[]{
                        new X509TrustManager() {

                            @Override
                            public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
                                trustManager.checkClientTrusted(x509Certificates, authType);
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                            }

                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return trustManager.getAcceptedIssuers();
                            }
                        }
                };
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);

                Certificate serverPubilcKeyCert = certificateFactory.generateCertificate(serverPubilcKeyCertInputStream);

                ByteArrayOutputStream outStream = new ByteArrayOutputStream();

                byte[] data = new byte[4096];
                int read = -1;
                while ((read = clientPrivateKeyFileInputStream.read(data)) != -1) {
                    outStream.write(data, 0, read);
                }

                String key = new String(outStream.toByteArray(), "ISO-8859-1");

                StringBuilder pkcs8Lines = new StringBuilder();
                BufferedReader bufferedReader = new BufferedReader(new StringReader(key));
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    pkcs8Lines.append(line);
                }

                String pkcs8Pem = pkcs8Lines.toString();
                pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
                pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
                pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

                byte[] encoderByte = Base64.decode(pkcs8Pem, Base64.DEFAULT);

                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoderByte);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                keyStore.setKeyEntry("server", privateKey, null, new Certificate[]{serverPubilcKeyCert});

                keyManagerFactory.init(keyStore, null);

                sslContext.init(keyManagerFactory.getKeyManagers(), wrappedTrustManagers, null);

                serverPubilcKeyCertInputStream.close();
                clientPrivateKeyFileInputStream.close();
                caCertInputStream.close();

                sslSocketFactory = sslContext.getSocketFactory();
            } else {
                Certificate serverPubilcKeyCert = certificateFactory.generateCertificate(serverPubilcKeyCertInputStream);
                Timber.d("【ServerPublicKey】" + serverPubilcKeyCert.getPublicKey());
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, serverPubilcKeyCertPwd == null ? null : serverPubilcKeyCertPwd.toCharArray());
                keyStore.setCertificateEntry("server", serverPubilcKeyCert);
                String algorithm = TrustManagerFactory.getDefaultAlgorithm();
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
                trustManagerFactory.init(keyStore);
                sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
                serverPubilcKeyCertInputStream.close();
                sslSocketFactory = sslContext.getSocketFactory();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return sslSocketFactory;
    }

    /**
     * get请求
     *
     * @param url
     * @return
     */
    public Single<String> get(String url) {
        return buildService(RetrofitService.class)
                .get(url)
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    Timber.d("【Url】" + url);
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【ErrorType】" + throwable.getClass().getName());
//                    Timber.d("【ErrorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * Get请求
     *
     * @param url
     * @param params
     * @return
     */
    public Single<String> get(String url, Map<String, String> params) {
        return buildService(RetrofitService.class)
                .get(url, params)
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    Timber.d("【Url】" + url);
                    PrintfUtil.d("【Params】", GsonUtil.toJson(params));
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【errorType】" + throwable.getClass().getName());
//                    Timber.d("【errorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * Post请求
     *
     * @param url
     * @return
     */
    public Single<String> post(String url) {
        return buildService(RetrofitService.class)
                .post(url)
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    Timber.d("【Url】" + url);
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【errorType】" + throwable.getClass().getName());
//                    Timber.d("【errorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * Post请求
     *
     * @param url
     * @param params
     * @return
     */
    public Single<String> post(String url, Map<String, String> params) {
        return buildService(RetrofitService.class)
                .post(url, params)
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    Timber.d("【Url】" + url);
                    PrintfUtil.d("【Params】", GsonUtil.toJson(params));
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【errorType】" + throwable.getClass().getName());
//                    Timber.d("【errorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * Post请求
     *
     * @param url
     * @param data
     * @return
     */
    public Single<String> post(String url, String data) {
        RequestBody body = RequestBody.create(MediaType.parse(contextType), data.getBytes());
        return buildService(RetrofitService.class)
                .post(url, body)
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    PrintfUtil.d("【Params】", data);
                })
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【errorType】" + throwable.getClass().getName());
//                    Timber.d("【errorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * Json请求
     *
     * @param url
     * @param jsonStr
     * @return
     */
    public Single<String> json(String url, String jsonStr) {
        RequestBody body = RequestBody.create(MediaType.parse(contextType), jsonStr);
        return buildService(RetrofitService.class)
                .json(url, body)
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .doOnSubscribe(disposable -> {
                    Timber.d("【Host】" + host);
                    Timber.d("【Url】" + url);
                    PrintfUtil.d("【Params】", jsonStr);
                })
                .onErrorResumeNext(throwable -> {
//                    Timber.d("【errorType】" + throwable.getClass().getName());
//                    Timber.e(throwable, "【errorMsg】" + throwable.getMessage());
                    if (throwable instanceof UnknownHostException) {
                        return Single.error(new UnknownHostException(UNKNOWN_HOST_EXCEPTION));
                    } else if (throwable instanceof ProtocolException) {
                        return Single.error(new UnknownHostException(PROTOCOL_EXCEPTION));
                    } else if (throwable instanceof ConnectException) {
                        return Single.error(new ConnectException(CONNECT_EXCEPTION));
                    } else if (throwable instanceof SocketTimeoutException) {
                        return Single.error(new SocketTimeoutException(TIMEOUT_EXCEPTION));
                    } else if (throwable instanceof SSLHandshakeException) {
                        return Single.error(new SSLHandshakeException(SSL_EXCEPTION));
                    } else if (throwable instanceof HttpException) {
                        HttpException exception = (HttpException) throwable;
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "【" + exception.code() + "】"));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("【Response】", response);
                    return response;
                });
    }

    /**
     * 下载
     *
     * @param url
     * @param saveFile
     * @return
     */
    public Observable<HttpProgress> download(String url, File saveFile) {
        return download(url, saveFile, true);
    }

    /**
     * 下载
     *
     * @param url
     * @param saveFile
     * @param overwrite
     * @return
     */
    public Observable<HttpProgress> download(String url, File saveFile, boolean overwrite) {
        if (overwrite) {
            if (saveFile.exists()) {
                saveFile.delete();
            }
        } else {
            if (saveFile.exists()) {
                if (saveFile.length() > 1) {
                    String range = "bytes=" + (saveFile.length() - 1) + "-";
                    Timber.d("[range]" + range);
                    addHeader("range", range);
                }
            }
        }
        long tag = System.currentTimeMillis();
        return buildService(RetrofitService.class)
                .download(url)
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .doOnSubscribe(disposable -> {
                    downloadMap.put(tag, disposable);
                    Timber.d("[host]" + RetrofitClient.this.getHost());
                    Timber.d("[url]" + url);
                    Timber.d("[saveFile]" + saveFile.getAbsolutePath());
                    if (!saveFile.exists()) {
                        saveFile.createNewFile();
                    }
                })
                .flatMapObservable(responseBody -> Observable.create((ObservableOnSubscribe<HttpProgress>) emitter -> {
                    HttpProgress progress = new HttpProgress();
                    progress.setUrl(host + url);
                    progress.setFilePath(saveFile.getAbsolutePath());
                    long contentLength = responseBody.contentLength();
                    Timber.d("[contentLength]" + contentLength);
                    if (saveFile.length() > 1) {
                        progress.setCur(saveFile.length() - 1);
                    } else {
                        progress.setCur(0);
                    }
                    Timber.d("[saveFileLength]" + (progress.getCur()));
                    progress.setTotal(contentLength + saveFile.length());
                    try {
                        InputStream inputStream = responseBody.byteStream();
                        RandomAccessFile randomAccessFile = new RandomAccessFile(saveFile, "rw");
                        randomAccessFile.seek(progress.getCur());
                        randomAccessFile.getFD().sync();
                        byte[] buffer = new byte[4096];
                        int read = 0;
                        while (downloadMap.get(tag) != null && !downloadMap.get(tag).isDisposed() && (read = inputStream.read(buffer)) != -1) {
                            if (downloadMap.get(tag) != null && downloadMap.get(tag).isDisposed()) {
                                downloadMap.remove(tag);
                                return;
                            }
                            progress.setCur(progress.getCur() + read);
                            progress.setPercent(FormatUtil.roundUp((double) progress.getCur() / (double) progress.getTotal() * 100));
                            Timber.d("[percent]" + progress.getPercent());
                            emitter.onNext(progress);
                        }
                        inputStream.close();
                        Timber.d("inputStream close");
                        randomAccessFile.close();
                        Timber.d("fileChannel close");
                        emitter.onComplete();
                        return;
                    } catch (InterruptedIOException e) {
                        Timber.d("interrupted");
                        if (e instanceof SocketTimeoutException) {
                            Timber.d("socket timeout");
                            emitter.onError(e);
                            return;
                        }
                        emitter.onComplete();
                        return;
                    }
                }))
                .doOnError(throwable -> {
                    if (throwable instanceof InterruptedIOException) {
                        Timber.d("error InterruptedIOException");
                    } else {
                        if (saveFile.exists()) {
                            saveFile.delete();
                        }
                        Timber.d("error and delete file");
                    }
                })
                .doOnDispose(() -> {
                    downloadMap.remove(tag);
                    Timber.d("download dispose");
                });
    }

}
