## Serve：

### KeyStore
  其中保存服务端的私钥

### Trust KeyStore
  其中保存客户端的授权证书

## Client
### KeyStore
  其中保存客户端的私钥

### Trust KeyStore
保存服务端的授权证书

 

在这里我还是推荐使用Java自带的keytool命令。当然目前非常流行的开源的生成SSL证书的还有OpenSSL。 OpenSSL用C语言编写，跨系统。但是我们可能在以后的过程中用java程序生成证书的方便性考虑，还是用JDK自带的keytool。

## 密钥产生

### 1）生成服务端私钥，并且导入到服务端KeyStore文件中
keytool -genkey -alias serverkey -keystore kserver.keystore
过程中，分别需要填写，根据需求自己设置就行
keystore密码：123456 
名字和姓氏：jin
组织单位名称：none
组织名称：none
城市或区域名称：BJ
州或省份名称：BJ
国家代码：CN
serverkey私钥的密码，不填写和keystore的密码一致。这里千万注意，直接回车就行了，不用修改密码。否则在后面的程序中无法直接应用这个私钥，会报错。
就可以生成kserver.keystore文件 
server.keystore是给服务端用的，其中保存着自己的私钥

### 2）根据私钥，导出服务端证书
keytool -export -alias serverkey -keystore kserver.keystore -file server.crt
server.crt就是服务端的证书

### 3）将服务端证书，导入到客户端的Trust KeyStore中
keytool -import -alias serverkey -file server.crt -keystore tclient.keystore
tclient.keystore是给客户端用的，其中保存着受信任的证书

##  采用同样的方法，生成客户端的私钥，客户端的证书，并且导入到服务端的Trust KeyStore中
### 1）keytool -genkey -alias clientkey -keystore kclient.keystore
### 2）keytool -export -alias clientkey -keystore kclient.keystore -file client.crt
### 3）keytool -import -alias clientkey -file client.crt -keystore tserver.keystore

如此一来，生成的文件分成两组
服务端保存：kserver.keystore tserver.keystore
客户端保存：kclient.keystore  tclient.kyestore