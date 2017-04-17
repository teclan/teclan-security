package teclan.security.rsa;

import java.util.Date;

import com.google.gson.annotations.SerializedName;
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

public class Certificate {
	/**
	 * 证书版本号
	 */
	public String version; 
	/**
	 * 签名算法 如：RSA
	 */
	public String algorithm = "RSA";  
	/**
	 * 证书序列号，由颁发机构生成
	 */
	public String serial="SSL"+new Date().getTime(); // 证书序列号，由颁发机构生成
	/**
	 * DN 证书颁发者的可识别名
	 */
	@SerializedName("DN") 
	public String distributedAuthority; 
	 
	/**
	 *  有效期—证书有效期的时间段。本字段由”Not Before”和”Not After”两项组成，
	 *   它们分别由UTC时间或一般的时间表示（在RFC2459中有详细的时间表示规则）
	 */
	public String notBefore; 
	/**
	 *  有效期—证书有效期的时间段。本字段由”Not Before”和”Not After”两项组成，
	 *   它们分别由UTC时间或一般的时间表示（在RFC2459中有详细的时间表示规则）
	 */
	public String notAfter;
	/**
	 * CN 公用名称
	 */
	@SerializedName("CN")
	public String commonName;  
	
	/**
	 * O 单位名称，对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端单位证书则为证书申请者所在单位名称； 
     * 证书申请单位所在地
	 */
	@SerializedName("OU")
	public String organizationUnit;  
	
	/**
	 * L 所在城市
	 */
	@SerializedName("L")
	public String locality; 
	/**
	 * S 所在省份 (State/Provice)
	 */
	@SerializedName("S")
	public String state;  
	
	/**
	 *  C 所在国家，国家字母缩写
	 */
	@SerializedName("C")
	public String country; 
	/**
	 *  邮件
	 */
	@SerializedName("E")
	public String email; 
	/**
	 *  电话
	 */
	public String phone;
	/**
	 * 街道
	 */
	@SerializedName("ST")
	public String stree;
	/**
	 * 邮政编码
	 */
	public String postalCode;
	/**
	 * 描述
	 */
	public String description;
	
	public String getDesForKey(){
		return String.format("CN=%s,OU=%s,L=%s,S=%s,C=%s,ST=%s", 
				commonName,organizationUnit,locality,state,country,stree);
	}
}
