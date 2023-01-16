package com.mirkowu.httpssslauthdemo;

import android.content.Context;
import android.util.Log;


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HttpsUtils {

    /**
     * 实现了 X509TrustManager
     * 通过此类中的 checkServerTrusted 方法来确认服务器证书是否正确
     */
    public static final class HttpsTrustManager implements X509TrustManager {
        X509Certificate cert;

        public HttpsTrustManager() {

        }

        public HttpsTrustManager(X509Certificate cert) {
            this.cert = cert;
        }

        @Override// 我们在客户端只做服务器端证书校验。
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            for (int i = 0; i < chain.length; i++) {
                Log.e("检验客户端证书", "证书内容：" + chain[i]);
            }
        }

        /**
         * @param chain 服务端返回的证书数组,因为服务器可能有多个https证书,我们在这里的
         *              逻辑就是拿到第一个证书,然后和本地证书判断,如果不一致,异常!!!
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            //             确认服务器端证书和代码中 hard code 的 CRT 证书相同。
            //            这里因为我们服务器只有一个证书,没有遍历,如果有多个,这里是for循环取出挨个判断
            for (int i = 0; i < chain.length; i++) {
                Log.e("校验服务端证书", "证书内容：" + chain[i]);
            }

            if (chain[0].equals(this.cert)) {
                return;
            }
            //throw new CertificateException("checkServerTrusted No trusted server cert found!");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{};
        }
    }

    private static final String TLS = "TLS";
    private static final String PROVIDER = "X509";
    private static final String STORE_TYPE = "BKS";
    private static final String TRUST_STORE_NAME = "server_trust_ks.bks";
    private static final String KEY_STORE_NAME = "client_ks.bks";

    private static final String CLIENT_KEY_STORE_PASSWORD = "client_password"; //密码
    private static final String CLIENT_TRUST_KEY_STORE_PASSWORD = "client";//密码

    /**
     * 关联Https请求验证证书
     */
    public static SSLSocketFactory getClientSSLContext(Context context) {

        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(PROVIDER);
            //生成信任证书Manager,默认系统会信任CA机构颁发的证书,自定的证书需要手动的加载
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(PROVIDER);

            KeyStore keyStoreKey = KeyStore.getInstance(STORE_TYPE);
            KeyStore keyStoreTrust = KeyStore.getInstance(STORE_TYPE);

            InputStream keyStream = context.getResources().openRawResource(R.raw.client_ks);
            InputStream trustStream = context.getResources().openRawResource(R.raw.server_trust_ks);

            //加载client端密钥
            keyStoreKey.load(keyStream, CLIENT_KEY_STORE_PASSWORD.toCharArray());
            //信任证书
            keyStoreTrust.load(trustStream, CLIENT_TRUST_KEY_STORE_PASSWORD.toCharArray());

            keyManagerFactory.init(keyStoreKey, CLIENT_KEY_STORE_PASSWORD.toCharArray());
            trustManagerFactory.init(keyStoreTrust);

            SSLContext sslContext = SSLContext.getInstance(TLS);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
                    null/* new SecureRandom()*/);
            //sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[] { new HttpsTrustManager(null) }, null/* new SecureRandom()*/);
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            return sslSocketFactory;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //秘钥的密码
    private static final String SERVER_KEY_STORE_PASSWORD = "server_password"; //秘钥的密码
    private static final String SERVER_TRUST_KEY_STORE_PASSWORD = "server";//密码

    /**
     * 关联Https请求验证证书
     */
    public static SSLServerSocketFactory getServerSSLContext(Context context, boolean needClientAuth) {
        try {
            //生成秘钥的manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(PROVIDER);
            //加载秘钥
            KeyStore keyStoreKey = KeyStore.getInstance(STORE_TYPE);
            InputStream keyStream = context.getResources().openRawResource(R.raw.server_ks);
            keyStoreKey.load(keyStream, SERVER_KEY_STORE_PASSWORD.toCharArray());
            //秘钥初始化
            keyManagerFactory.init(keyStoreKey, SERVER_KEY_STORE_PASSWORD.toCharArray());


            //初始化SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS);
            if (needClientAuth) {
                //加载信任的证书
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(PROVIDER);
                KeyStore keyStoreTrust = KeyStore.getInstance(STORE_TYPE);
                InputStream trustStream = context.getResources().openRawResource(R.raw.client_trust_ks);
                keyStoreTrust.load(trustStream, SERVER_TRUST_KEY_STORE_PASSWORD.toCharArray());
                //秘钥初始化
                trustManagerFactory.init(keyStoreTrust);

                sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            } else {
                sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            }
            //也可以自定义TrustManager 用于查看证书或自定义校验规则
            //sslContext.init(keyManagerFactory.getKeyManagers(),new TrustManager[]{new HttpsUtils.HttpsTrustManager(null)}, null);

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            return sslServerSocketFactory;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }
}
