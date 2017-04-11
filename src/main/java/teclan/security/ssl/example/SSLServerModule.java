package teclan.security.ssl.example;

import com.google.inject.AbstractModule;

import teclan.security.ssl.SSLServer;

public class SSLServerModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(SSLServer.class).toProvider(SSLServerProvider.class)
                .asEagerSingleton();

    }

}
