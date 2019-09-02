package teclan.security.rsa;

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
import java.security.MessageDigest;
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

import teclan.security.utils.base64.BASE64Decoder;
import teclan.security.utils.base64.BASE64Encoder;
import teclan.utils.FileUtils;

public class RSAUtils {
	private static final Logger LOGGER = LoggerFactory.getLogger(RSAUtils.class);
	
	private static final String DEFAULT_PUB_KEY="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLcuZKy/LnODIA03JE+KTOoXq6TCIGVkUw6BOiJQ0v871VXW5GsqHf0AODf4qpblAkzMPURGOx3iwr53Xe37o11GS4kbwg08FModUXcr4kA+kYQEXlWgh+fs3kgcuzvwlZMogANu7LxUz+0PFgL+NaiNmZgU4LNq76r3bLYXd6lQIDAQAB";
	private static final String DEFAULT_PRI_KEY= "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIty5krL8uc4MgDTckT4pM6herpMIgZWRTDoE6IlDS/zvVVdbkayod/QA4N/iqluUCTMw9REY7HeLCvndd7fujXUZLiRvCDTwUyh1RdyviQD6RhAReVaCH5+zeSBy7O/CVkyiAA27svFTP7Q8WAv41qI2ZmBTgs2rvqvdsthd3qVAgMBAAECgYBynhdRhT7688KN0T5MGH8F485HUAprYP9wCmEQ1hl3v4RwpOHeNDc/Ce/JZsynJKe1B6UyVKAI848k6xOEBCo9j7wuGajAQO0pzhtMxPLFr/7AayE+Ax4h+k4UrgVbuuaB3crwQsw+Hcol8GVXBWUnnWdrQy+GKP69ppfMRzzQ5QJBAPm0a8Q6ERyR3I+QsTFSrDKbqzx9Bqdgy53S+8W1iDE1l2b3l0oQSEXeyVrokq0YrFEUVjLZ0MM/3l907ep0AMsCQQCO9uTEingIhXyhe0zfHh08sP4LtWYB/xiEbkKz6Ybe+8rv/N6znmwun5fA2c8BInjwtjpOpScyP/ytvNYgf+YfAkEA9r+D0ncy25GDa1am0j+Iq8XKM0602Yc8Diwj4V4eQ8paX0SAeo6WbHzXan7yGhyMgt5ew4cb1STy4E8SnyCcewJAFDuW1sXuBO63W7cyguUlKCC4Y3nRrPioRJ3CLOog30/tQZedAPirwNFvTajFphh120M+70BqUq9BmGkAOOtA6wJAYwlehf7MHNQNMTIHyfnOKeXyU0R3oVkRut3aUxEQCEyAV52dgw/zPbqPcMw77U+emK1h1AsoZhAAopwDcleUQg==";
	
	public static String PUB_KEY = DEFAULT_PUB_KEY;
	public static String PRI_KEY=DEFAULT_PRI_KEY;

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
			
			if(filePath!=null){
			    String pubKeyFile =  filePath + "/publicKey.keystore";
	            String priKeyFile =  filePath + "/privateKey.keystore";
	            FileUtils.creatIfNeed(pubKeyFile);
	            FileUtils.creatIfNeed(priKeyFile);
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
			}
			
			RSA rsa = new RSA(publicKey, privateKey);

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
	public static PublicKey getPublicKey(String key)  {
		byte[] keyBytes;
		try{
		keyBytes = (new BASE64Decoder()).decodeBuffer(key);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
		}catch(Exception e){
		    LOGGER.error(e.getMessage(),e);
		    return null;
		}
	}

	/**
	 * 得到私钥
	 * 
	 * @param key
	 *            密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String key)  {
		byte[] keyBytes;
		try{
		keyBytes = (new BASE64Decoder()).decodeBuffer(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
		}catch(Exception e){
		    LOGGER.error(e.getMessage(),e);
		    return null;
		}
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
	 * 使用keystore对明文进行加密
	 * 
	 * @param publicKeystore
	 *            公钥文件路径
	 * @param plainText
	 *            明文
	 * @return
	 */
	public static String encryptWithPubKeyStore(String publicKeystore, String plainText) {
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
	public static String encryptWithPubKey(String publicKey, String plainText) {
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
	public static String decryptWitPriKey(PrivateKey privateKey, String enStr) {
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
	public static String decryptWitPriKey(String privateKey, String enStr) {
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
	public static String decryptWitPriKeyStore(String privateKeystore, String enStr) {
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
	
	/** 
     * 公钥加密过程 
     *  
     * @param publicKey 
     *            公钥 
     * @param plainTextData 
     *            明文数据 
     * @return 
     * @throws Exception 
     *             加密过程中的异常信息 
     */  
    public static byte[] encryptWithPubKey(PublicKey publicKey, byte[] plainTextData)  
            throws Exception {  
        if (publicKey == null) {  
            throw new Exception("加密公钥为空, 请设置");  
        }  
        Cipher cipher = null;  
        try {  
            // 使用默认RSA  
            cipher = Cipher.getInstance("RSA");  
            // cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());  
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
            byte[] output = cipher.doFinal(plainTextData);  
            return output;  
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此加密算法");  
        } catch (NoSuchPaddingException e) {  
            e.printStackTrace();  
            return null;  
        } catch (InvalidKeyException e) {  
            throw new Exception("加密公钥非法,请检查");  
        } catch (IllegalBlockSizeException e) {  
            throw new Exception("明文长度非法");  
        } catch (BadPaddingException e) {  
            throw new Exception("明文数据已损坏");  
        }  
    }  
    
    /** 
     * 私钥解密过程 
     *  
     * @param privateKey 
     *            私钥 
     * @param cipherData 
     *            密文数据 
     * @return 明文 
     * @throws Exception 
     *             解密过程中的异常信息 
     */  
    public static byte[] decryptWithPriKey( PrivateKey privateKey, byte[] cipherData)  
            throws Exception {  
        if (privateKey == null) {  
            throw new Exception("解密私钥为空, 请设置");  
        }  
        Cipher cipher = null;  
        try {  
            // 使用默认RSA  
            cipher = Cipher.getInstance("RSA");  
            // cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());  
            cipher.init(Cipher.DECRYPT_MODE, privateKey);  
            byte[] output = cipher.doFinal(cipherData);  
            return output;  
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此解密算法");  
        } catch (NoSuchPaddingException e) {  
            e.printStackTrace();  
            return null;  
        } catch (InvalidKeyException e) {  
            throw new Exception("解密私钥非法,请检查");  
        } catch (IllegalBlockSizeException e) {  
            throw new Exception("密文长度非法");  
        } catch (BadPaddingException e) {  
            throw new Exception("密文数据已损坏");  
        }  
    }  
    
    /** 
     * 私钥加密过程 
     *  
     * @param privateKey 
     *            私钥 
     * @param plainTextData 
     *            明文数据 
     * @return 
     * @throws Exception 
     *             加密过程中的异常信息 
     */  
    public static byte[] encryptWithPriKey(PrivateKey privateKey, byte[] plainTextData)  
            throws Exception {  
        if (privateKey == null) {  
            throw new Exception("加密私钥为空, 请设置");  
        }  
        Cipher cipher = null;  
        try {  
            // 使用默认RSA  
            cipher = Cipher.getInstance("RSA");  
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
            byte[] output = cipher.doFinal(plainTextData);  
            return output;  
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此加密算法");  
        } catch (NoSuchPaddingException e) {  
            e.printStackTrace();  
            return null;  
        } catch (InvalidKeyException e) {  
            throw new Exception("加密私钥非法,请检查");  
        } catch (IllegalBlockSizeException e) {  
            throw new Exception("明文长度非法");  
        } catch (BadPaddingException e) {  
            throw new Exception("明文数据已损坏");  
        }  
    }  
    

    /** 
     * 公钥解密过程 
     *  
     * @param publicKey 
     *            公钥 
     * @param cipherData 
     *            密文数据 
     * @return 明文 
     * @throws Exception 
     *             解密过程中的异常信息 
     */  
    public static byte[] decryptWithPubKey( PublicKey publicKey, byte[] cipherData)  
            throws Exception {  
        if (publicKey == null) {  
            throw new Exception("解密公钥为空, 请设置");  
        }  
        Cipher cipher = null;  
        try {  
            // 使用默认RSA  
            cipher = Cipher.getInstance("RSA");  
            // cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());  
            cipher.init(Cipher.DECRYPT_MODE, publicKey);  
            byte[] output = cipher.doFinal(cipherData);  
            return output;  
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("无此解密算法");  
        } catch (NoSuchPaddingException e) {  
            e.printStackTrace();  
            return null;  
        } catch (InvalidKeyException e) {  
            throw new Exception("解密公钥非法,请检查");  
        } catch (IllegalBlockSizeException e) {  
            throw new Exception("密文长度非法");  
        } catch (BadPaddingException e) {  
            throw new Exception("密文数据已损坏");  
        }  
    }  
  
    public static String sign(String plainText,PrivateKey privateKey)  
            throws Exception  {  
        /* 
         * MD5加密 
         */  
        MessageDigest md5 = MessageDigest.getInstance("MD5");  
        md5.update(plainText.getBytes("utf-8"));  
        byte[] digestBytes = md5.digest();  
        /* 
         * 用私钥进行签名 RSA 
         * Cipher负责完成加密或解密工作，基于RSA 
         */  
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        //ENCRYPT_MODE表示为加密模式  
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
        //加密  
        byte[] rsaBytes = cipher.doFinal(digestBytes);  
        //Base64编码  
     return   new BASE64Encoder().encode(rsaBytes);
       // return Base64.byteArrayToBase64(rsaBytes); 
    }
    
    public static String sign(String plainText)  
            throws Exception  {  
        /* 
         * MD5加密 
         */  
        MessageDigest md5 = MessageDigest.getInstance("MD5");  
        md5.update(plainText.getBytes("utf-8"));  
        byte[] digestBytes = md5.digest();  
        /* 
         * 用私钥进行签名 RSA 
         * Cipher负责完成加密或解密工作，基于RSA 
         */  
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        //ENCRYPT_MODE表示为加密模式  
        
        
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(PRI_KEY));  
        //加密  
        byte[] rsaBytes = cipher.doFinal(digestBytes);  
        //Base64编码  
     return   new BASE64Encoder().encode(rsaBytes);
       // return Base64.byteArrayToBase64(rsaBytes); 
    }
    
    /**
     * 验证签名
     * @param message 要验证的消息
     * @param cipherText 签名信息
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static boolean verify(String message, String cipherText,PublicKey publicKey) throws Exception {  
        Cipher c4 = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        // 根据密钥，对Cipher对象进行初始化,DECRYPT_MODE表示解密模式  
        c4.init(Cipher.DECRYPT_MODE, publicKey);  
        // 解密  
//        byte[] desDecTextBytes = c4.doFinal(Base64.base64ToByteArray(cipherText));  
        byte[] desDecTextBytes = c4.doFinal( new BASE64Decoder().decodeBuffer(cipherText));  
        // 得到前置对原文进行的MD5  
        String md5Digest1 =  new BASE64Encoder().encode(desDecTextBytes); //;Base64.byteArrayToBase64(desDecTextBytes);  
        MessageDigest md5 = MessageDigest.getInstance("MD5");  
        md5.update(message.getBytes("utf-8"));  
        byte[] digestBytes = md5.digest();  
        // 得到商户对原文进行的MD5  
        String md5Digest2 = new BASE64Encoder().encode(digestBytes);//Base64.byteArrayToBase64(digestBytes);  
        // 验证签名  
        if (md5Digest1.equals(md5Digest2)) {  
            return true;  
        } else {  
            return false;  
        }  
    }  
    
    /**
     * 验证签名
     * @param message 要验证的消息
     * @param cipherText 签名信息
     * @return
     * @throws Exception
     */
    public static boolean verify(String message, String cipherText) throws Exception {  
        Cipher c4 = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        // 根据密钥，对Cipher对象进行初始化,DECRYPT_MODE表示解密模式  
        c4.init(Cipher.DECRYPT_MODE, getPublicKey(PUB_KEY));  
        // 解密  
//        byte[] desDecTextBytes = c4.doFinal(Base64.base64ToByteArray(cipherText));  
        byte[] desDecTextBytes = c4.doFinal( new BASE64Decoder().decodeBuffer(cipherText));  
        // 得到前置对原文进行的MD5  
        String md5Digest1 =  new BASE64Encoder().encode(desDecTextBytes); //;Base64.byteArrayToBase64(desDecTextBytes);  
        MessageDigest md5 = MessageDigest.getInstance("MD5");  
        md5.update(message.getBytes("utf-8"));  
        byte[] digestBytes = md5.digest();  
        // 得到商户对原文进行的MD5  
        String md5Digest2 = new BASE64Encoder().encode(digestBytes);//Base64.byteArrayToBase64(digestBytes);  
        // 验证签名  
        if (md5Digest1.equals(md5Digest2)) {  
            return true;  
        } else {  
            return false;  
        }  
    }  
    
    
	
}
