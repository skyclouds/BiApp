package com.biapp;

import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;

import androidx.fragment.app.FragmentActivity;

import com.f2prateek.rx.preferences2.BuildConfig;

import org.jetbrains.annotations.NotNull;

import timber.log.Timber;

/**
 * @author Yun
 */
public abstract class BIActivity extends FragmentActivity {
    protected final String TAG = this.getClass().getSimpleName() + "(" + this.hashCode() + ")";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Timber.d(TAG, "【onCreate】");
        super.onCreate(savedInstanceState);
        if (!BuildConfig.DEBUG) {
            // 禁止截屏
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        Timber.d(TAG, "【onNewIntent】");
        super.onNewIntent(intent);
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        Timber.i(TAG, ":onPostCreate");
        super.onPostCreate(savedInstanceState);
    }


    @Override
    protected void onRestart() {
        Timber.d(TAG, "【onRestart】");
        super.onRestart();
    }

    @Override
    protected void onStart() {
        Timber.i(TAG, ":onStart");
        super.onStart();
    }

    @Override
    public void onBackPressed() {
        Timber.d(TAG, "【onBackPressed】");
        super.onBackPressed();
    }

    @Override
    protected void onResume() {
        Timber.d(TAG, "【onResume】");
        super.onResume();
    }

    @Override
    protected void onPostResume() {
        Timber.i(TAG, ":onPostResume");
        super.onPostResume();
    }

    @Override
    protected void onPause() {
        Timber.d(TAG, "【onPause】");
        super.onPause();
    }

    @Override
    public void onSaveInstanceState(@NotNull Bundle outState) {
        Timber.i(TAG, ":onSaveInstanceState");
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onStop() {
        Timber.d(TAG, "【onStop】");
        super.onStop();
    }

    @Override
    public void finish() {
        Timber.d(TAG, "【finish】");
        super.finish();
    }

    @Override
    protected void onDestroy() {
        Timber.d(TAG, "【onDestroy】");
        super.onDestroy();
    }
}
