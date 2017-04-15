package teclan.security.rsa;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import teclan.utils.GsonUtils;

/**
 * 
一般的数字证书产品的主题通常含有如下字段：
公用名称 (Common Name) 简称：CN 字段，对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端证书则为证书申请者的姓名； 
单位名称 (Organization Name) ：简称：O 字段，对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端单位证书则为证书申请者所在单位名称； 
证书申请单位所在地： 
所在城市 (Locality) 简称：L 字段 
所在省份 (State/Provice) 简称：S 字段 
所在国家 (Country) 简称：C 字段，只能是国家字母缩写，如中国：CN 
其他一些字段：
电子邮件 (Email) 简称：E 字段 
多个姓名字段 简称：G 字段 
介绍：Description 字段 
电话号码：Phone 字段，格式要求 + 国家区号 城市区号 电话号码，如： +86 732 88888888 
地址：STREET  字段 
邮政编码：PostalCode 字段 
显示其他内容 简称：OU 字段
 * @author teclan
 *
 */

@JsonIgnoreProperties("CER")
public class Certificate {
	
	public String version; // 证书版本号
	public String algorithm; // 签名算法 如：RSA
	public String serial; // 证书序列号，由颁发机构生成
	@JsonProperty("DN")
	public String distributedAuthority;//DN 证书颁发者的可识别名
	// 有效期—证书有效期的时间段。本字段由”Not Before”和”Not After”两项组成，
	// 它们分别由UTC时间或一般的时间表示（在RFC2459中有详细的时间表示规则）
	public String notBefore; 
	public String notAfter;
	@JsonProperty("CN")
	public String commonName; //CN 公用名称
	@JsonProperty("ON")
	public String organizationUnit; //ON 单位名称
	@JsonProperty("L")
	public String locality; // L 所在城市
	@JsonProperty("S")
	public String state; // S 所在省份 (State/Provice)
	public String country; // C 所在国家，国家字母缩写
	public String email; 
	public String phone;
	public String stree; //街道
	public String postalCode;// 邮政编码
	public String description;
	
	public static void main(String[] args) {
		Certificate certificate = new Certificate();
		certificate.distributedAuthority="Teclan";
		certificate.commonName="teclan";
		certificate.country="ZN";
		
		System.out.println(GsonUtils.toJson(certificate));
	}

}
