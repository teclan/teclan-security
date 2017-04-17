package teclan.security.rsa;

import java.io.File;
import java.io.IOException;

import com.google.inject.Singleton;

@Singleton
public class CertificateFactory {

	public static String JAVA_HOME;

	static {
		JAVA_HOME = System.getProperty("java.home");
	}

	public void generateByKeyTool(Certificate certificate,String serverKeyStorePath,String clientKeyStorePath,String password) {

		File serverKeyFile = new File(serverKeyStorePath);
		File clientKeyFile = new File(clientKeyStorePath);
//		new File(serverKeyFile.getParent()).mkdirs();
//		new File(clientKeyFile.getParent()).mkdirs();
		
		try {
			Process ps = Runtime.getRuntime().exec(generateCmdForServerKey(certificate,serverKeyStorePath,password));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
	}

	public String generateCmdForServerKey(Certificate certificate,String serverKeyStorePath,String password) {
		
		StringBuffer cmd = new StringBuffer();
		cmd.append(JAVA_HOME);
		cmd.append(" keytool -genkey -v -alias "+serverKeyStorePath+" -keyalg RSA -keysize 1024 -validity 365");  
		cmd.append(" -keystore "+serverKeyStorePath);  
		cmd.append(String.format(" -keypass %s -storepass %s ", password,password)); 
		cmd.append(String.format(" -dname \"%s\"", certificate.getDesForKey()));  
		return cmd.toString();
	}

	public static void main(String[] args) {

		StringBuffer cmd = new StringBuffer();

		cmd.append(JAVA_HOME + "/bin");

		cmd.toString();

	}

}
