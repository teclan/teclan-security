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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Test;
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
	
}
