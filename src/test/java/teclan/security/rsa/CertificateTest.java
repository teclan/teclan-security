package teclan.security.rsa;

import org.junit.Assert;
import org.junit.Test;


import teclan.utils.GsonUtils;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class CertificateTest {
	
	@Test
	public   void main( ) throws JSONException {
		Certificate certificate = new Certificate();
		certificate.distributedAuthority="Teclan";
		certificate.commonName="teclan";
		certificate.country="ZN";
		
		String json = GsonUtils.toJson(certificate);
		
		JSONObject object = new JSONObject(json);
		
		System.out.println(json);
		
		Assert.assertEquals("Teclan", object.get("DN"));
		
		certificate = GsonUtils.fromJson(json, Certificate.class);
		
		Assert.assertEquals("Teclan", certificate.distributedAuthority);
	}


}
