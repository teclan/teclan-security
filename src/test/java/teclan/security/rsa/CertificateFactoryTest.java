package teclan.security.rsa;

import org.junit.Test;

public class CertificateFactoryTest {
	
	
	// 必须以root权限执行
	@Test
	public void generateTest(){
		Certificate certificate = new Certificate();
		certificate.distributedAuthority="Teclan";
		certificate.commonName="teclan";
		certificate.country="ZN";
		
		CertificateFactory factory = new CertificateFactory();
		
		factory.generateByKeyTool(certificate, "/home/teclan/1.keystore", "1.p12","123456");
		
	}

}
