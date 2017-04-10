package teclan.ssl.generate;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import teclan.ssl.generate.base64.BASE64Decoder;
import teclan.ssl.generate.base64.BASE64Encoder;

public class RSAUtils {
	private static final Logger LOGGER = LoggerFactory.getLogger(RSAUtils.class);

	private static Cipher cipher;

	static {
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			LOGGER.error(e.getMessage(), e);
		}
	}

	public static RSA generateKeyPair() {
		return generateKeyPair(null);
	}
	
	public static RSA generateKeyPair(String filePath){
		return generateKeyPair(1024,filePath);
	}

	/**
	 * 生成密钥对
	 * 
	 * @param keySize
	 *   密钥位数，1024的整数倍，推荐1024，2048，过大影响性能
	 * @param filePath
	 *            生成密钥的路径
	 * @return
	 */
	public static RSA generateKeyPair(int keySize,String filePath) {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			// 密钥位数,1024的倍数
			keyPairGen.initialize(keySize);
			// 密钥对
			KeyPair keyPair = keyPairGen.generateKeyPair();
			// 公钥
			PublicKey publicKey = keyPair.getPublic();
			// 私钥
			PrivateKey privateKey = keyPair.getPrivate();
			// 得到公钥字符串
			String publicKeyString = getKeyString(publicKey);
			// 得到私钥字符串
			String privateKeyString = getKeyString(privateKey);
			// 将密钥对写入到文件

			String pubKeyFile = filePath == null ? "publicKey.keystore" : filePath + "/publicKey.keystore";
			String priKeyFile = filePath == null ? "privateKey.keystore" : filePath + "/privateKey.keystore";
			FileWriter pubfw = new FileWriter(pubKeyFile);
			FileWriter prifw = new FileWriter(priKeyFile);
			BufferedWriter pubbw = new BufferedWriter(pubfw);
			BufferedWriter pribw = new BufferedWriter(prifw);
			pubbw.write(publicKeyString);
			pribw.write(privateKeyString);
			pubbw.flush();
			pubbw.close();
			pubfw.close();
			pribw.flush();
			pribw.close();
			prifw.close();
			RSA rsa = new RSA(publicKeyString, privateKeyString);

			return rsa;
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			return null;
		}
	}

	/**
	 * 得到公钥
	 * 
	 * @param key
	 *            密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static PublicKey getPublicKey(String key) throws Exception {
		byte[] keyBytes;
		keyBytes = (new BASE64Decoder()).decodeBuffer(key);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	/**
	 * 得到私钥
	 * 
	 * @param key
	 *            密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String key) throws Exception {
		byte[] keyBytes;
		keyBytes = (new BASE64Decoder()).decodeBuffer(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

	/**
	 * 得到密钥字符串（经过base64编码）
	 * 
	 * @return
	 */
	public static String getKeyString(Key key) throws Exception {
		byte[] keyBytes = key.getEncoded();
		String s = (new BASE64Encoder()).encode(keyBytes);
		return s;
	}

	/**
	 * 使用公钥对明文进行加密，返回BASE64编码的字符串
	 * 
	 * @param publicKey
	 * @param plainText
	 * @return
	 */
	public static String encrypt(PublicKey publicKey, String plainText) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] enBytes = cipher.doFinal(plainText.getBytes());
			return (new BASE64Encoder()).encode(enBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(), e);
		}
		return null;
	}

	/**
	 * 使用keystore对明文进行加密
	 * 
	 * @param publicKeystore
	 *            公钥文件路径
	 * @param plainText
	 *            明文
	 * @return
	 */
	public static String fileEncrypt(String publicKeystore, String plainText) {
		try {
			FileReader fr = new FileReader(publicKeystore);
			BufferedReader br = new BufferedReader(fr);
			String publicKeyString = "";
			String str;
			while ((str = br.readLine()) != null) {
				publicKeyString += str;
			}
			br.close();
			fr.close();
			cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKeyString));
			byte[] enBytes = cipher.doFinal(plainText.getBytes());
			return (new BASE64Encoder()).encode(enBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
		return null;
	}

	/**
	 * 使用公钥对明文进行加密
	 * 
	 * @param publicKey
	 *            公钥
	 * @param plainText
	 *            明文
	 * @return
	 */
	public static String encrypt(String publicKey, String plainText) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
			byte[] enBytes = cipher.doFinal(plainText.getBytes());
			return (new BASE64Encoder()).encode(enBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (Exception e) {
			LOGGER.error(e.getMessage(),e);  
		}
		return null;
	}

	/**
	 * 使用私钥对明文密文进行解密
	 * 
	 * @param privateKey
	 * @param enStr
	 * @return
	 */
	public static String decrypt(PrivateKey privateKey, String enStr) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));
			return new String(deBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IOException e) {
			LOGGER.error(e.getMessage(),e);  
		}
		return null;
	}

	/**
	 * 使用私钥对密文进行解密
	 * 
	 * @param privateKey
	 *            私钥
	 * @param enStr
	 *            密文
	 * @return
	 */
	public static String decrypt(String privateKey, String enStr) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
			byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));
			return new String(deBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IOException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (Exception e) {
			LOGGER.error(e.getMessage(),e);  
		}
		return null;
	}

	/**
	 * 使用keystore对密文进行解密
	 * 
	 * @param privateKeystore
	 *            私钥路径
	 * @param enStr
	 *            密文
	 * @return
	 */
	public static String fileDecrypt(String privateKeystore, String enStr) {
		try {
			FileReader fr = new FileReader(privateKeystore);
			BufferedReader br = new BufferedReader(fr);
			String privateKeyString = "";
			String str;
			while ((str = br.readLine()) != null) {
				privateKeyString += str;
			}
			br.close();
			fr.close();
			cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKeyString));
			byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));
			return new String(deBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IllegalBlockSizeException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (BadPaddingException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (IOException e) {
			LOGGER.error(e.getMessage(),e);  
		} catch (Exception e) {
			LOGGER.error(e.getMessage(),e);  
		}
		return null;
	}
}
