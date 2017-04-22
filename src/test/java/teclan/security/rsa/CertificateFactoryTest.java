package teclan.security.rsa;

import org.junit.Test;

public class CertificateFactoryTest {
	
	@Test
	public void generateTest(){
		Certificate certificate = new Certificate();
		certificate.distributedAuthority="Teclan";
		certificate.commonName="teclan";
		certificate.country="ZN";
		
		CertificateFactory factory = new CertificateFactory();
		
		RSA rsa = RSAUtils.generateKeyPair();
		
		certificate.publicKey = rsa.getPublicKeyString();
		certificate.privateKey = rsa.getPrivateKeyString();
		
		factory.generateCert(certificate, "teclan.cert.xml");
		
		
	}

}
