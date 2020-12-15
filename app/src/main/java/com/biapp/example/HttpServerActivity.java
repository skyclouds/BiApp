package com.biapp.example;

import android.os.Bundle;
import android.widget.Button;
import android.widget.RadioGroup;
import android.widget.TextView;

import com.biapp.BIActivity;
import com.biapp.http.HttpServer;
import com.biapp.util.DeviceInfoUtil;

import java.util.Map;

/**
 * @author yun
 */
public class HttpServerActivity extends BIActivity {

    private Button btn_start, btn_stop;
    private RadioGroup rp;
    private TextView tv_info;
    private MyHttpServer httpServer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        httpServer = new MyHttpServer();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_http);
        btn_start = findViewById(R.id.btn_start);
        btn_start.setOnClickListener(v -> {
            httpServer.startListener(new String[]{"test"});
            tv_info.setText("start Http Server in " + DeviceInfoUtil.getIpAddress(this) + ":" + httpServer.getPort());
        });
        btn_stop = findViewById(R.id.btn_stop);
        btn_stop.setOnClickListener(v -> {
            httpServer.stopListener();
            tv_info.setText("stop!");
        });
        tv_info = findViewById(R.id.tv_info);
    }

    private class MyHttpServer extends HttpServer {
        @Override
        protected void handlerRequest(String url, Map<String, String> headers, Map<String, String> query, String body) {
            httpServer.sendResponse("hello!");
        }
    }
}
