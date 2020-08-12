package com.biapp;

import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;

import androidx.fragment.app.FragmentActivity;

import com.biapp.util.PrintfUtil;

import org.jetbrains.annotations.NotNull;

/**
 * @author Yun
 */
public abstract class BIActivity extends FragmentActivity {
    protected final String TAG = this.getClass().getSimpleName() + "(" + this.hashCode() + ")";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        PrintfUtil.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        if (!BuildConfig.DEBUG) {
            // 禁止截屏
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        PrintfUtil.d(TAG, "onNewIntent");
        super.onNewIntent(intent);
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        PrintfUtil.d(TAG, "onPostCreate");
        super.onPostCreate(savedInstanceState);
    }


    @Override
    protected void onRestart() {
        PrintfUtil.d(TAG, "onRestart");
        super.onRestart();
    }

    @Override
    protected void onStart() {
        PrintfUtil.d(TAG, "onStart");
        super.onStart();
    }

    @Override
    public void onBackPressed() {
        PrintfUtil.i(TAG, "onBackPressed");
        super.onBackPressed();
    }

    @Override
    protected void onResume() {
        PrintfUtil.d(TAG, "onResume");
        super.onResume();
    }

    @Override
    protected void onPostResume() {
        PrintfUtil.d(TAG, "onPostResume");
        super.onPostResume();
    }

    @Override
    protected void onPause() {
        PrintfUtil.d(TAG, "onPause");
        super.onPause();
    }

    @Override
    public void onSaveInstanceState(@NotNull Bundle outState) {
        PrintfUtil.i(TAG, "onSaveInstanceState");
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onStop() {
        PrintfUtil.d(TAG, "onStop");
        super.onStop();
    }

    @Override
    public void finish() {
        PrintfUtil.d(TAG, "finish");
        super.finish();
    }

    @Override
    protected void onDestroy() {
        PrintfUtil.d(TAG, "onDestroy");
        super.onDestroy();
    }
}
