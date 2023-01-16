package com.mirkowu.httpssslauthdemo;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.List;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import fi.iki.elonen.SimpleWebServer;

public class HttpsWebServer extends SimpleWebServer {
    public HttpsWebServer(String host, int port, File wwwroot, boolean quiet, String cors) {
        super(host, port, wwwroot, quiet, cors);
    }

    public HttpsWebServer(String host, int port, File wwwroot, boolean quiet) {
        super(host, port, wwwroot, quiet);
    }

    public HttpsWebServer(String host, int port, List<File> wwwroots, boolean quiet) {
        super(host, port, wwwroots, quiet);
    }

    public HttpsWebServer(String host, int port, List<File> wwwroots, boolean quiet, String cors) {
        super(host, port, wwwroots, quiet, cors);
    }

    @Override
    public void init() {
//        mutualAuth();
    }

    /**
     * 设置双向认证，要在start之前调用，也可以直接在init中设置
     *
     * @param context
     */
    public void mutualAuth(Context context) {
        SSLServerSocketFactory sslServerSocketFactory = HttpsUtils.getServerSSLContext(context, true);
        makeSecure(sslServerSocketFactory, null, true);
    }

    /**
     * 设置单向认证，要在start之前调用，也可以直接在init中设置
     * <p>
     * 常用的https，单向认证，客户端校验服务端
     *
     * @param context
     */
    public void singleAuth(Context context) {
        SSLServerSocketFactory sslServerSocketFactory = HttpsUtils.getServerSSLContext(context, false);
        makeSecure(sslServerSocketFactory, null, false);
    }


    public void makeSecure(SSLServerSocketFactory sslServerSocketFactory, String[] sslProtocols, boolean needClientAuth) {
        setServerSocketFactory(new MutualAuthSecureServerSocketFactory(sslServerSocketFactory, sslProtocols, needClientAuth));
    }

    /**
     * Creates a new MutualAuth SSLServerSocket
     */
    public static class MutualAuthSecureServerSocketFactory implements ServerSocketFactory {

        private SSLServerSocketFactory sslServerSocketFactory;

        private String[] sslProtocols;

        private boolean needClientAuth;

        public MutualAuthSecureServerSocketFactory(SSLServerSocketFactory sslServerSocketFactory,
                                                   String[] sslProtocols, boolean needClientAuth) {
            this.sslServerSocketFactory = sslServerSocketFactory;
            this.sslProtocols = sslProtocols;
            this.needClientAuth = needClientAuth;
        }

        @Override
        public ServerSocket create() throws IOException {
            SSLServerSocket ss = null;
            ss = (SSLServerSocket) this.sslServerSocketFactory.createServerSocket();
            if (this.sslProtocols != null) {
                ss.setEnabledProtocols(this.sslProtocols);
            } else {
                ss.setEnabledProtocols(ss.getSupportedProtocols());
            }
            ss.setUseClientMode(false);
            ss.setWantClientAuth(false);
            ss.setNeedClientAuth(needClientAuth);//设置为true，开启客户端认证
            return ss;
        }
    }
}
