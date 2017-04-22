package teclan.security.rsa;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import teclan.security.utils.base64.BASE64Encoder;

public class RSA {

    private PublicKey  publicKey;
    private PrivateKey privateKey;

    public RSA() {

    }

    public RSA(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;

    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPublicKeyString() {
        return getKeyString(publicKey);
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getPrivateKeyString() {
        return getKeyString(privateKey);
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * 得到密钥字符串（经过base64编码）
     * 
     * @return
     */
    public String getKeyString(Key key) {
        byte[] keyBytes = key.getEncoded();
        String s = (new BASE64Encoder()).encode(keyBytes);
        return s;
    }

}
