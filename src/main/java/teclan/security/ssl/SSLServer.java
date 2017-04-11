package teclan.security.ssl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSLServer implements Runnable, HandshakeCompletedListener {
    private static final Logger      LOGGER       = LoggerFactory
            .getLogger(SSLServer.class);

    private static Map<String, Date> CERTIFICATES = new ConcurrentHashMap<String, Date>();

    private int                      port;
    private String                   keyStore;
    private String                   keyStorePwd;
    private String                   catKeyStorePwd;
    private String                   tKeyStore;
    private String                   tKeyStorePwd;
    private Socket                   socket;

    private String                   peerCerName;

    public SSLServer(int port, String keyStore, String keyStorePwd,
            String tKeyStore, String tKeyStorePwd) {
        this(port, keyStore, keyStorePwd, keyStorePwd, tKeyStore, tKeyStorePwd);
    }

    public SSLServer(int port, String keyStore, String keyStorePwd,
            String catKeyStorePwd, String tKeyStore, String tKeyStorePwd) {
        this.port = port;
        this.keyStore = keyStore;
        this.keyStorePwd = keyStorePwd;
        this.catKeyStorePwd = catKeyStorePwd;
        this.tKeyStore = tKeyStore;
        this.tKeyStorePwd = tKeyStorePwd;
    }

    public void doInit() throws Exception {
        KeyStore serverKeyStore = KeyStore.getInstance("JKS");

        if (!new File(keyStore).exists()) {
            LOGGER.error("ssl server init failed,file doesn't exists : {} ",
                    new File(keyStore).getAbsolutePath());
            return;

        }

        if (!new File(tKeyStore).exists()) {
            LOGGER.error("ssl server init failed,file doesn't exists : {} ",
                    new File(tKeyStore).getAbsolutePath());
            return;
        }

        serverKeyStore.load(new FileInputStream(keyStore),
                keyStorePwd.toCharArray());

        KeyStore serverTrustKeyStore = KeyStore.getInstance("JKS");
        serverTrustKeyStore.load(new FileInputStream(tKeyStore),
                tKeyStorePwd.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKeyStore, catKeyStorePwd.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(serverTrustKeyStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLServerSocketFactory sslServerSocketFactory = sslContext
                .getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
                .createServerSocket(port);
        sslServerSocket.setNeedClientAuth(true);

        LOGGER.info("\nSSLSocket Server is start on {} ", port);

        while (true) {
            SSLSocket s = (SSLSocket) sslServerSocket.accept();
            this.socket = s;
            s.addHandshakeCompletedListener(this);
            new Thread(this).start();
        }
    }

    public void init() {

        new Thread(new Runnable() {

            @Override
            public void run() {
                try {
                    doInit();
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }

            }
        }).start();
    }

    @Override
    public void run() {
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(),
                    true);

            String line;
            LOGGER.debug("shake hands message : ");
            while ((line = reader.readLine()) != null && !"done".equals(line)) {
                LOGGER.debug("{}", line);
            }
            writer.println("ssl certificate success !");
            LOGGER.info("ssl certificate success : {}", peerCerName);
            CERTIFICATES.put(getRemoteIp(socket), new Date());
        } catch (Exception e) {
            LOGGER.error("ssl handshak failed,bad_certificate : {}",
                    socket.getRemoteSocketAddress());
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent event) {
        try {
            X509Certificate cert = (X509Certificate) event
                    .getPeerCertificates()[0];
            peerCerName = cert.getSubjectX500Principal().getName();
        } catch (SSLPeerUnverifiedException ex) {
            ex.printStackTrace();
        }
    }

    public void setSSLSocket(SSLSocket socket) {
        if (this.socket == null) {
            this.socket = socket;
        } else {
            LOGGER.warn("SSLSocket already inited !");
        }
    }

    public boolean isCertificated(String ip) {
        return CERTIFICATES.get(ip) != null;
    }

    public void delete(String ip) {
        CERTIFICATES.remove(ip);
    }

    private String getRemoteIp(Socket socket) {
        return ((SSLSocket) socket).getSession().getPeerHost();
    }
}