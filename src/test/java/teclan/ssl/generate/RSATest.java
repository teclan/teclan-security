package teclan.ssl.generate;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSATest {
	private static final Logger LOGGER = LoggerFactory.getLogger(RSATest.class);
	
	@Test
	public void test() {
		RSA rsa = RSAUtils.generateKeyPair();
		String publicKey = rsa.getPubKey();
		String privateKey=rsa.getPriKey();
		LOGGER.info("\n公钥：\n{}\n私钥：\n{}",publicKey,privateKey);
		String source = "　4月6日至7日，国家主席习近平赴美国佛罗里达州海湖庄园。";
		LOGGER.info("\n明文：{}",source);
		String enData = RSAUtils.encrypt(publicKey, source);
		LOGGER.info("\n公钥加密：{}",enData);
		String deData = RSAUtils.decrypt(privateKey, enData);
		LOGGER.info("\n私钥解密：{}",deData);
		Assert.assertEquals(source, deData);
	}

}
