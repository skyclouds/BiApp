package com.biapp;

import android.app.Service;
import android.content.Intent;

import com.biapp.util.PrintfUtil;

/**
 * BIService
 *
 * @author Yun
 */
public abstract class BIService extends Service {
    protected final String TAG = this.getClass().getSimpleName() + "(" + this.hashCode() + ")";

    @Override
    public void onCreate() {
        PrintfUtil.d(TAG, "onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        PrintfUtil.d(TAG, ":onStartCommand");
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public boolean onUnbind(Intent intent) {
        PrintfUtil.d(TAG, "onUnbind");
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        PrintfUtil.d(TAG, "onDestroy");
        super.onDestroy();
    }
}
