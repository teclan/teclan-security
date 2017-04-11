package teclan.security.ssl.example;

import com.google.inject.AbstractModule;

import teclan.security.ssl.SSLClient;

public class SSLCilentModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(SSLClient.class).toProvider(SSLClientProvider.class)
                .asEagerSingleton();

    }

}
