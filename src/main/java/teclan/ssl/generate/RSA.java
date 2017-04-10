package teclan.ssl.generate;

public class RSA {
	private String pubKey;
	private String priKey;
	
	public RSA(){
		
	}
	
	public RSA(String pubKey,String priKey){
		this.pubKey=pubKey;
		this.priKey=priKey;
	}

	public String getPubKey() {
		return pubKey;
	}

	public void setPubKey(String pubKey) {
		this.pubKey = pubKey;
	}

	public String getPriKey() {
		return priKey;
	}

	public void setPriKey(String priKey) {
		this.priKey = priKey;
	}
	
	

}
