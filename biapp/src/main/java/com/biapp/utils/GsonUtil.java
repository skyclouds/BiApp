package com.biapp.utils;


import android.text.TextUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;

import java.lang.reflect.Type;

/**
 * @author Yun
 */
public class GsonUtil {

    public static String toJson(Object obj) {
        if (obj == null) {
            return null;
        }
        Gson gson = new Gson();
        return gson.toJson(obj);
    }

    public static String toJson(Object obj, Type type, TypeAdapter adapter) {
        if (obj == null) {
            return null;
        }
        Gson gson = new GsonBuilder().registerTypeAdapter(type, adapter).create();
        return gson.toJson(obj);
    }

    public static String toJsonWithExpose(Object obj) {
        if (obj == null) {
            return null;
        }
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        return gson.toJson(obj);
    }

    public static <T> T toObject(String json, Class<T> cls) {
        if (TextUtils.isEmpty(json)) {
            return null;
        }
        Gson gson = new Gson();
        return gson.fromJson(json, cls);
    }

    public static <T> T toObject(String json, Class<T> cls, TypeAdapter adapter) {
        if (TextUtils.isEmpty(json)) {
            return null;
        }
        Gson gson = new GsonBuilder().registerTypeAdapter(cls, adapter).create();
        return gson.fromJson(json, cls);
    }


    public static <T> T toObjectWithExpose(String json, Class<T> cls) {
        if (TextUtils.isEmpty(json)) {
            return null;
        }
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        return gson.fromJson(json, cls);
    }

    public static <T> T toObject(String json, Type type) {
        if (TextUtils.isEmpty(json)) {
            return null;
        }
        Gson gson = new Gson();
        return gson.fromJson(json, type);
    }

    public static <T> T toObjectWithExpose(String json, Type type) {
        if (TextUtils.isEmpty(json)) {
            return null;
        }
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        return gson.fromJson(json, type);
    }
}
