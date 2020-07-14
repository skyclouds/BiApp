package com.biapp.example;

import android.os.Bundle;
import android.widget.TextView;

import com.biapp.BIActivity;
import com.biapp.BIApp;
import com.biapp.util.ApkInfoUtil;
import com.biapp.util.ToastUtil;

/**
 * @author yun
 */
public class MainActivity extends BIActivity {

    private TextView tv_version_name, tv_version_code;
    private long exitTime;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tv_version_name = findViewById(R.id.tv_version_name);
        tv_version_name.setText(getString(R.string.label_version_name) + ApkInfoUtil.getVersionName(this));
        tv_version_code = findViewById(R.id.tv_version_code);
        tv_version_code.setText(getString(R.string.label_version_code) + ApkInfoUtil.getVersionCode(this));
    }

    @Override
    public void onBackPressed() {
        if ((System.currentTimeMillis() - exitTime) > 2000) {
            exitTime = System.currentTimeMillis();
            ToastUtil.showShort(BIApp.getContext(), getString(R.string.confirm_to_exit_app));
        } else {
            BIApp.getInstance().exit();
        }
    }
}
