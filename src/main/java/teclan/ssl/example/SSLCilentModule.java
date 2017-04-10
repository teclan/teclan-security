package teclan.ssl.example;

import com.google.inject.AbstractModule;

import teclan.ssl.SSLClient;

public class SSLCilentModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(SSLClient.class).toProvider(SSLClientProvider.class)
                .asEagerSingleton();

    }

}
