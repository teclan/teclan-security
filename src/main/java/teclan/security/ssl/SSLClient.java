package teclan.security.ssl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import teclan.security.ssl.exception.CertificateException;

public class SSLClient {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(SSLClient.class);

    private int                 port;
    private String              keyStore;
    private String              keyStorePwd;
    private String              catKeyStorePwd;
    private String              tKeyStore;
    private String              tKeyStorePwd;

    private SSLSocketFactory    socketFactory;

    private Socket              socket;

    public SSLClient(int port, String keyStore, String keyStorePwd,
            String tKeyStore, String tKeyStorePwd) {
        this(port, keyStore, keyStorePwd, keyStorePwd, tKeyStore, tKeyStorePwd);
    }

    public SSLClient(int port, String keyStore, String keyStorePwd,
            String catKeyStorePwd, String tKeyStore, String tKeyStorePwd) {
        this.port = port;
        this.keyStore = keyStore;
        this.keyStorePwd = keyStorePwd;
        this.catKeyStorePwd = catKeyStorePwd;
        this.tKeyStore = tKeyStore;
        this.tKeyStorePwd = tKeyStorePwd;

        init();
    }

    private void init() {
        try {

            if (!new File(keyStore).exists()) {
                LOGGER.error("file {} is not exists",
                        new File(keyStore).getAbsolutePath());
                return;
            }

            if (!new File(tKeyStore).exists()) {
                LOGGER.error("file {} is not exists",
                        new File(tKeyStore).getAbsolutePath());
                return;
            }

            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(new FileInputStream(keyStore),
                    keyStorePwd.toCharArray());

            KeyStore clientTrustKeyStore = KeyStore.getInstance("JKS");
            clientTrustKeyStore.load(new FileInputStream(tKeyStore),
                    tKeyStorePwd.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientKeyStore, catKeyStorePwd.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(clientTrustKeyStore);

            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            socketFactory = sslContext.getSocketFactory();

        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * 
     * SSL 认证
     * 
     * @param host
     *            远程 SSL 主机
     * @throws CertificateException
     */
    public void certificate(String host) throws CertificateException {
        certificate(host, port, null);
    }

    /**
     * SSL 认证
     * 
     * @param host
     *            远程 SSL 主机
     * @param port
     *            远程 SSL 主机 认证端口
     * @throws CertificateException
     */
    public void certificate(String host, int port) throws CertificateException {
        certificate(host, port, null);
    }

    public void certificate(String host, int port, String message)
            throws CertificateException {

        LOGGER.info("It going to certificate(SSL) with remote port : {}", port);
        try {
            socket = socketFactory.createSocket(host, port);

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            if (message != null) {
                send(message, out);
            }
            send("done", out);
            receive(in);

            LOGGER.info("\nssl certificate success !");

        } catch (Exception e) {
            throw new CertificateException(
                    "ssl handshak failed,Received fatal alert: bad_certificate");
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

    public void send(String s, PrintWriter out) throws IOException {
        LOGGER.debug("sending : {} ", s);
        out.println(s);
    }

    public void receive(BufferedReader in) throws IOException {
        String s;
        while ((s = in.readLine()) != null) {
            LOGGER.info("Reveived : {} ", s);
        }
    }

    public int getPort() {
        return port;
    }
}