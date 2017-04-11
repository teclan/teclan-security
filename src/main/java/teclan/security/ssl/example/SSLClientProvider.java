package teclan.security.ssl.example;

import com.google.inject.Provider;
import com.google.inject.Singleton;

import teclan.security.ssl.SSLClient;

@Singleton
public class SSLClientProvider implements Provider<SSLClient> {

    private static final int    DEFAULT_SSL_SERVER_PORT    = 11123;
    private static final String DEFAULT_KEY_STORE          = "certs/client/kclient.keystore_lisi";
    private static final String DEFAULT_KEY_STORE_PWD      = "123456";
    private static final String DEFAULT_CAT_KEY_STORE      = "123456";
    private static final String DEFAULT_TRUE_KEY_STORE     = "certs/client/tclient.keystore";
    private static final String DEFAULT_TRUE_KEY_STORE_PWD = "123456";

    @Override
    public SSLClient get() {
        return new SSLClient(DEFAULT_SSL_SERVER_PORT, DEFAULT_KEY_STORE,
                DEFAULT_KEY_STORE_PWD, DEFAULT_CAT_KEY_STORE,
                DEFAULT_TRUE_KEY_STORE, DEFAULT_TRUE_KEY_STORE_PWD);
    }

}
