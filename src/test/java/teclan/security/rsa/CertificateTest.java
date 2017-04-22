package teclan.security.rsa;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import teclan.utils.GsonUtils;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class CertificateTest {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(CertificateTest.class);

    @Test
    public void jsonTest() throws JSONException {
        Certificate certificate = new Certificate();
        certificate.distributedAuthority = "Teclan";
        certificate.commonName = "teclan";
        certificate.country = "ZN";

        String json = GsonUtils.toJson(certificate);

        JSONObject object = new JSONObject(json);

        System.out.println(json);

        Assert.assertEquals("Teclan", object.get("DN"));

        certificate = GsonUtils.fromJson(json, Certificate.class);

        Assert.assertEquals("Teclan", certificate.distributedAuthority);
    }

    @Test
    public void vaildTest() {
        Certificate certificate = new Certificate();
        certificate.distributedAuthority = "Teclan";
        certificate.commonName = "teclan";
        certificate.country = "ZN";

        certificate.generateSignature();

        boolean result = certificate.validCert();

        Assert.assertTrue(result);
    }
    
    @Test
    public void vaildTest1() {
        Certificate certificate = new Certificate();
        certificate.distributedAuthority = "Teclan";
        certificate.commonName = "teclan";
        certificate.country = "ZN";
        
        RSA rsa = RSAUtils.generateKeyPair();

        certificate.generateSignature(rsa.getPrivateKey());

        boolean result = certificate.validCert(rsa.getPublicKey());

        Assert.assertTrue(result);
    }

}
