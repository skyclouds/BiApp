package com.biapp;

import android.app.Application;
import android.content.Context;
import android.os.StrictMode;


import com.biapp.room.AppDatabase;
import com.f2prateek.rx.preferences2.BuildConfig;
import com.biapp.messenger.RxBusDefaults;
import io.reactivex.plugins.RxJavaPlugins;
import timber.log.Timber;

/**
 * The type Soter kld.
 *
 * @author Yun
 */
public class BIApp extends Application {

    private final String TAG = this.getClass().getSimpleName();
    private static BIApp instance;
    private static Context context;


    @Override
    public void onCreate() {
        context = getApplicationContext();
        instance = this;
        init();
        super.onCreate();
//        if (LeakCanary.isInAnalyzerProcess(this)) {
//            // This process is dedicated to LeakCanary for heap analysis.
//            // You should not init your app in this process.
//            return;
//        }
//        LeakCanary.install(this);
        Timber.d(TAG, "【onCreate】");
        setRxJavaUnCatchErrorHandler();
    }

    /**
     * 获取实例
     *
     * @return 实例对象
     */
    public static BIApp getInstance() {
        return instance;
    }

    /**
     * 获取 Context
     *
     * @return context
     */
    public static Context getContext() {
        return context;
    }

    /**
     * 初始化应用
     */
    public void init() {
        initLog();
        Timber.d(TAG ,"【init】");
        //init RxBus
        RxBusDefaults.get().setSendToSuperClassesAsWell(true);
        // init database.
        AppDatabase.init(getApplicationContext());
        strictMode();
    }

    /**
     * 日志初始化
     */
    private void initLog() {
        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
        }
    }

    /**
     * Open strict mode when debug.
     */
    private void strictMode() {
        if (BuildConfig.DEBUG) {
            StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build());
            StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                    .detectAll()
                    .penaltyLog()
                    .build());
        }
    }

    /**
     * 退出应用
     */
    public void exit() {
        Timber.d(TAG, "【exit】");
        onDestory();
        android.os.Process.killProcess(android.os.Process.myPid());
        onTerminate();
    }

    /**
     * Destory
     */
    public void onDestory() {
        Timber.d(TAG, "【onDestory】");
    }

    @Override
    public void onTerminate() {
        Timber.d(TAG, "【onTerminate】");
        super.onTerminate();
    }


    /**
     * 设置Rxjava捕获异常
     */
    private void setRxJavaUnCatchErrorHandler() {
        RxJavaPlugins.setErrorHandler(Timber::e);
    }
}
