package teclan.security.ssl.example;

import com.google.inject.Provider;
import com.google.inject.Singleton;

import teclan.security.ssl.SSLServer;

@Singleton
public class SSLServerProvider implements Provider<SSLServer> {

    private static final int    DEFAULT_SSL_SERVER_PORT    = 11123;
    private static final String DEFAULT_KEY_STORE          = "certs/server/kserver.keystore";
    private static final String DEFAULT_KEY_STORE_PWD      = "123456";
    private static final String DEFAULT_CAT_KEY_STORE      = "123456";
    private static final String DEFAULT_TRUE_KEY_STORE     = "certs/server/tserver.keystore";
    private static final String DEFAULT_TRUE_KEY_STORE_PWD = "123456";

    @Override
    public SSLServer get() {
        return new SSLServer(DEFAULT_SSL_SERVER_PORT, DEFAULT_KEY_STORE,
                DEFAULT_KEY_STORE_PWD, DEFAULT_CAT_KEY_STORE,
                DEFAULT_TRUE_KEY_STORE, DEFAULT_TRUE_KEY_STORE_PWD);
    }

}
