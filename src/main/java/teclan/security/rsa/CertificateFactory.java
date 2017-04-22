package teclan.security.rsa;

import java.io.File;
import java.io.IOException;

import com.google.inject.Singleton;

import teclan.utils.JacksonUtils;

@Singleton
public class CertificateFactory {

    // public static String JAVA_HOME;
    //
    // static {
    // JAVA_HOME = System.getProperty("java.home");
    // }
    //
    // public void generateByKeyTool(Certificate certificate,
    // String serverKeyStorePath, String clientKeyStorePath,
    // String password) {
    //
    // File serverKeyFile = new File(serverKeyStorePath);
    // File clientKeyFile = new File(clientKeyStorePath);
    // // new File(serverKeyFile.getParent()).mkdirs();
    // // new File(clientKeyFile.getParent()).mkdirs();
    //
    // try {
    // Process ps = Runtime.getRuntime().exec(generateCmdForServerKey(
    // certificate, serverKeyStorePath, password));
    // } catch (IOException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }
    //
    // }
    //
    // public String generateCmdForServerKey(Certificate certificate,
    // String serverKeyStorePath, String password) {
    //
    // StringBuffer cmd = new StringBuffer();
    // cmd.append(JAVA_HOME);
    // cmd.append(" keytool -genkey -v -alias " + serverKeyStorePath
    // + " -keyalg RSA -keysize 1024 -validity 365");
    // cmd.append(" -keystore " + serverKeyStorePath);
    // cmd.append(String.format(" -keypass %s -storepass %s ", password,
    // password));
    // cmd.append(String.format(" -dname \"%s\"", getDesForKey(certificate)));
    // return cmd.toString();
    // }
    //
    // public String getDesForKey(Certificate certificate) {
    // return String.format("CN=%s,OU=%s,L=%s,S=%s,C=%s,ST=%s",
    // certificate.commonName, certificate.organizationUnit,
    // certificate.locality, certificate.state, certificate.country,
    // certificate.stree);
    // }

    public void generateCert(Certificate certificate, String certFilePath) {
       // certificate.generateSignature();
        JacksonUtils.object2xml(certificate, certFilePath);
    }

}
