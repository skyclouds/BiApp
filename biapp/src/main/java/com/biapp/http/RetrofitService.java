package com.biapp.http;

import java.util.Map;

import io.reactivex.Single;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.QueryMap;
import retrofit2.http.Streaming;
import retrofit2.http.Url;

/**
 *
 * @author Yun
 */
public interface RetrofitService {
    /***
     * Get请求
     *
     * @param url
     *            URL
     * @return
     */
    @GET
    Single<ResponseBody> get(@Url String url);

    /***
     * Get请求
     *
     * @param url
     *            URL
     * @param params
     *            参数
     * @return
     */
    @GET
    Single<ResponseBody> get(@Url String url, @QueryMap Map<String, String> params);

    /***
     * Post请求
     *
     * @param url
     *            URL
     * @return
     */
    @POST
    Single<ResponseBody> post(@Url String url);

    /***
     * Post请求
     * @param body
     * @return
     */
    @POST
    Single<ResponseBody> post(@Url String url, @Body RequestBody body);

    /***
     * Post请求
     *
     * @param url
     *            URL
     * @param params
     *            参数
     * @return
     */
    @POST
    Single<ResponseBody> post(@Url String url, @QueryMap Map<String, String> params);

    /***
     * Post请求
     *
     * @param url
     *            URL
     * @param body
     * @return
     */
    @POST
    Single<ResponseBody> json(@Url String url, @Body RequestBody body);


    @Streaming
    @GET
    Single<ResponseBody> download(@Url String downloadUrl);


}
