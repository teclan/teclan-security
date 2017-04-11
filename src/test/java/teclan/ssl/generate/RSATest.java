package teclan.ssl.generate;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSATest {
	private static final Logger LOGGER = LoggerFactory.getLogger(RSATest.class);
	
	@Test
	public void testPubKeyEnAndPriKeyDe() throws Exception {
		RSA rsa = RSAUtils.generateKeyPair();
		String publicKey = rsa.getPublicKeyString();
		String privateKey=rsa.getPrivateKeyString();
		
		LOGGER.info("\n公钥：\n{}\n私钥：\n{}",publicKey,privateKey);
		
		String source = "　4月6日至7日，国家主席习近平赴美国佛罗里达州海湖庄园。";
		
		LOGGER.info("\n明文：{}",source);
		
		String enData = RSAUtils.encryptWithPubKey(publicKey, source);
		LOGGER.info("\n公钥加密：{}",enData);
		
		String deData = RSAUtils.decryptWitPriKey(privateKey, enData);
		LOGGER.info("\n私钥解密：{}",deData);
		
		Assert.assertEquals(source, deData);
	}
	
	@Test
	public void testPriKeyEnAndPubKeyDe() throws Exception {
		RSA rsa = RSAUtils.generateKeyPair();
		String publicKey = rsa.getPublicKeyString();
		String privateKey=rsa.getPrivateKeyString();
		
		LOGGER.info("\n公钥：\n{}\n私钥：\n{}",publicKey,privateKey);
		
		String source = "　4月6日至7日，国家主席习近平赴美国佛罗里达州海湖庄园。";
		
		LOGGER.info("\n明文：{}",source);
		
		byte[] enData = RSAUtils.encryptWithPriKey(rsa.getPrivateKey(), source.getBytes());
		LOGGER.info("\n私钥加密：{}",new String(enData));
		
		byte[] deData = RSAUtils.decryptWithPubKey(rsa.getPublicKey(), enData);
		LOGGER.info("\n公钥解密：{}",new String(deData));
		
		Assert.assertEquals(source, new String(deData));
	}
	
	@Test
	public void signTest() throws Exception{
		RSA rsa = RSAUtils.generateKeyPair();
		String message = "　4月6日至7日，国家主席习近平赴美国佛罗里达州海湖庄园。";
		String sign = RSAUtils.sign(message, rsa.getPrivateKey());
		boolean verify = RSAUtils.verify(message, sign, rsa.getPublicKey());
		Assert.assertEquals(verify, true);
		
	}

}
