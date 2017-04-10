package teclan.ssl.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Guice;
import com.google.inject.Injector;

import teclan.ssl.SSLClient;

public class Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Server.class);

    public static void main(String[] args) {
        Injector injector = Guice.createInjector(new SSLCilentModule());

        try {
            injector.getInstance(SSLClient.class).certificate("localhost");

        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
    }

}
