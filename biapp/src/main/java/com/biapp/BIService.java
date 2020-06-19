package com.biapp;

import android.app.Service;
import android.content.Intent;

import timber.log.Timber;

/**
 * BIService
 *
 * @author Yun
 */
public abstract class BIService extends Service {
    protected final String TAG = this.getClass().getSimpleName() + "(" + this.hashCode() + ")";

    @Override
    public void onCreate() {
        Timber.d(TAG, "【onCreate】");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Timber.d(TAG, ":onStartCommand");
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public boolean onUnbind(Intent intent) {
        Timber.d(TAG, "【onUnbind】");
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        Timber.d(TAG, "【onDestroy】");
        super.onDestroy();
    }
}
