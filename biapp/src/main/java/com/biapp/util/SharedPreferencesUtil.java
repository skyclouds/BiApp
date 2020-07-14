package com.biapp.util;

import android.content.Context;
import android.preference.PreferenceManager;

import com.f2prateek.rx.preferences2.Preference;
import com.f2prateek.rx.preferences2.RxSharedPreferences;


/**
 * @author Yun
 */
public class SharedPreferencesUtil {
    private static Context context;
    private static RxSharedPreferences rxPreferences;

    public static void init(Context appContext) {
        context = appContext;
        if (rxPreferences == null) {
            android.content.SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
            rxPreferences = RxSharedPreferences.create(preferences);
        }
    }

    public static Preference<Boolean> getBoolean(String key) {
        return rxPreferences.getBoolean(key);
    }

    public static Preference<Boolean> getBoolean(String key, Boolean defaultValue) {
        return rxPreferences.getBoolean(key, defaultValue);
    }

    public static Preference<Float> getFloat(String key) {
        return rxPreferences.getFloat(key);
    }

    public static Preference<Float> getFloat(String key, Float defaultValue) {
        return rxPreferences.getFloat(key, defaultValue);
    }

    public static Preference<Integer> getInteger(String key) {
        return rxPreferences.getInteger(key);
    }

    public static Preference<Integer> getInteger(String key, Integer defaultValue) {
        return rxPreferences.getInteger(key, defaultValue);
    }

    public static Preference<Long> getLong(String key) {
        return rxPreferences.getLong(key);
    }

    public static Preference<Long> getLong(String key, Long defaultValue) {
        return rxPreferences.getLong(key, defaultValue);
    }

    public static Preference<String> getString(String key) {
        return rxPreferences.getString(key);
    }

    public static Preference<String> getString(String key, String defaultValue) {
        return rxPreferences.getString(key, defaultValue);
    }

    public static <T> Preference<T> get(String key, Class<T> cls) {
        try {
            return rxPreferences.getObject(key, cls.newInstance(), new GsonPreferenceAdapter(cls));
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static class GsonPreferenceAdapter<T> implements Preference.Converter<T> {
        private Class<T> cls;

        public GsonPreferenceAdapter(Class<T> cls) {
            this.cls = cls;
        }

        @Override
        public T deserialize(String serialized) {
            return GsonUtil.toObject(serialized, cls);
        }

        @Override
        public String serialize(T value) {
            return GsonUtil.toJson(value);
        }
    }

}
