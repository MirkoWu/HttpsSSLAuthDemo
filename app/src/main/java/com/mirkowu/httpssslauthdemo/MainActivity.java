package com.mirkowu.httpssslauthdemo;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;

import java.io.IOException;
import java.security.Permissions;
import java.util.Collections;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class MainActivity extends AppCompatActivity {

    public static final int SERVER_PORT = 8080;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, 1);
        }
    }


    public void startLocalServer(View view) {
        startHttpsServer();
    }

    public void jumpBrowser(View view) {
        //单向认证时可通过浏览器访问
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://127.0.0.1:" + SERVER_PORT)));
    }

    public void requestMutualAuth(View view) {
        httpsRequest(this, "https://127.0.0.1:" + SERVER_PORT);
    }


    private void startHttpsServer() {
        try {
            HttpsWebServer httpsWebServer = new HttpsWebServer(null, SERVER_PORT, Environment.getExternalStorageDirectory(), false);
            httpsWebServer.mutualAuth(this);//双向认证
//            httpsWebServer.singleAuth(this);//单向认证
            httpsWebServer.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void httpsRequest(Context context, String url) {
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .allEnabledTlsVersions()
                .allEnabledCipherSuites()
                .build();
        SSLSocketFactory sslSocketFactory = HttpsUtils.getClientSSLContext(context);
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                //.connectionSpecs(Collections.singletonList(spec)) //开启全部的tls协议和加密
                .sslSocketFactory(sslSocketFactory, new HttpsUtils.HttpsTrustManager())
                .hostnameVerifier((hostname, session) -> true)//这里可以校验域名
                .build();

        Request request = new Request.Builder().url(url).build();
        okHttpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.e("request", "error:" + e.toString());
                e.printStackTrace();
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                ResponseBody body = response.body();
                if (response.isSuccessful()) {
                    Log.e("request", "success:${}" + body.string());
                } else {
                    Log.e("request", "error,statusCode=" + response.code() + ",body" + body.string());
                }
            }
        });
    }
}