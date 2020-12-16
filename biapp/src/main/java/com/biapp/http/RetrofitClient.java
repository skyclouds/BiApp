package com.biapp.http;


import com.biapp.BIApp;
import com.biapp.BIAppException;
import com.biapp.lib.R;
import com.biapp.util.FormatUtil;
import com.biapp.util.GsonUtil;
import com.biapp.util.PrintfUtil;

import java.io.File;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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
import retrofit2.HttpException;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import retrofit2.converter.gson.GsonConverterFactory;


/**
 * @author Yun
 * @date 2017/12/6
 */
public class RetrofitClient {

    private String host;
    private HttpHeader header;
    private SSLContext sslContext;
    private X509TrustManager trustManager;
    private OkHttpClient.Builder okHttpClientBuilder;
    private OkHttpClient okHttpClient;
    private retrofit2.Retrofit.Builder retrofitBuilder;
    private retrofit2.Retrofit retrofit;
    private String sslProtocol = "TLSv1.2";
    private String contextType = "application/json";
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

    public RetrofitClient setContextType(String contextType) {
        this.contextType = contextType;
        return this;
    }

    public RetrofitClient setSSLProtocol(String sslProtocol) {
        this.sslProtocol = sslProtocol;
        return this;
    }

    public RetrofitClient initSSLContext(KeyManagerFactory keyManagerFactory, TrustManagerFactory trustManagerFactory) {
        try {
            this.sslContext = SSLContext.getInstance(sslProtocol);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new IllegalStateException("Unexpected default trust managers:"
                        + Arrays.toString(trustManagers));
            }
            trustManager = (X509TrustManager) trustManagers[0];
            sslContext.init(keyManagerFactory == null ? null : keyManagerFactory.getKeyManagers(),
                    new TrustManager[]{trustManager},
                    null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
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
        if (this.sslContext != null) {
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            okHttpClientBuilder.sslSocketFactory(sslSocketFactory);
            okHttpClientBuilder.hostnameVerifier((hostname, session) -> true);
        }
        //设置头部
        if (this.header != null && !this.header.getHeaders().isEmpty()) {
            PrintfUtil.d("Header", GsonUtil.toJson(header.getHeaders()));
            okHttpClientBuilder.addInterceptor(header);
        }
        // 设置同时连接的个数和时间，默认5个，和每个保持时间为10s
        okHttpClientBuilder.connectionPool(new ConnectionPool(5, 10, TimeUnit.SECONDS));
        return okHttpClientBuilder;
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Url", url);
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("ErrorType", throwable.getClass().getName());
//                    PrintfUtil.d("ErrorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Url", url);
                    PrintfUtil.d("Params", GsonUtil.toJson(params));
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("errorType", throwable.getClass().getName());
//                    PrintfUtil.d("errorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Url", url);
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("errorType", throwable.getClass().getName());
//                    PrintfUtil.d("errorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Url", url);
                    PrintfUtil.d("Params", GsonUtil.toJson(params));
                })
                .subscribeOn(Schedulers.io())
                .observeOn(Schedulers.io())
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("errorType", throwable.getClass().getName());
//                    PrintfUtil.d("errorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Params", data);
                })
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("errorType", throwable.getClass().getName());
//                    PrintfUtil.d("errorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("Host", host);
                    PrintfUtil.d("Url", url);
                    PrintfUtil.d("Params", jsonStr);
                })
                .onErrorResumeNext(throwable -> {
//                    PrintfUtil.d("errorType", throwable.getClass().getName());
//                    PrintfUtil.e(throwable, "errorMsg", throwable.getMessage());
                    PrintfUtil.e(throwable);
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
                        return Single.error(new BIAppException(HTTP_EXCEPTION + "" + exception.code() + ""));
                    }
                    return Single.error(throwable);
                })
                .map(responseBody -> {
                    String response = responseBody.string();
                    PrintfUtil.d("Response", response);
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
                    PrintfUtil.d("range", range);
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
                    PrintfUtil.d("host", RetrofitClient.this.getHost());
                    PrintfUtil.d("url", url);
                    PrintfUtil.d("saveFile", saveFile.getAbsolutePath());
                    if (!saveFile.exists()) {
                        saveFile.createNewFile();
                    }
                })
                .flatMapObservable(responseBody -> Observable.create((ObservableOnSubscribe<HttpProgress>) emitter -> {
                    HttpProgress progress = new HttpProgress();
                    progress.setUrl(host + url);
                    progress.setFilePath(saveFile.getAbsolutePath());
                    long contentLength = responseBody.contentLength();
                    PrintfUtil.d("contentLength", contentLength + "");
                    if (saveFile.length() > 1) {
                        progress.setCur(saveFile.length() - 1);
                    } else {
                        progress.setCur(0);
                    }
                    PrintfUtil.d("saveFileLength", progress.getCur() + "");
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
                            PrintfUtil.d("percent", progress.getPercent() + "");
                            emitter.onNext(progress);
                        }
                        inputStream.close();
                        randomAccessFile.close();
                        emitter.onComplete();
                        return;
                    } catch (InterruptedIOException e) {
                        if (e instanceof SocketTimeoutException) {
                            PrintfUtil.i("SocketTimeoutException", "download cancel");
                            emitter.onError(e);
                            return;
                        }
                        emitter.onComplete();
                        return;
                    }
                }))
                .doOnError(throwable -> {
                    if (throwable instanceof InterruptedIOException) {
                        PrintfUtil.i("InterruptedIOException", "download cancel");
                    } else {
                        if (saveFile.exists()) {
                            saveFile.delete();
                        }
                    }
                })
                .doOnDispose(() -> {
                    downloadMap.remove(tag);
                    PrintfUtil.i("Dispose", "download dispose");
                });
    }

}
