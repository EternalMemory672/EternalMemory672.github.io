## IPsec(3)
#IPsec
（英语：Internet Protocol Security，缩写为IPsec），是一个[协议](https://baike.baidu.com/item/%E5%8D%8F%E8%AE%AE/13020269)包，通过对[IP协议](https://baike.baidu.com/item/IP%E5%8D%8F%E8%AE%AE/131947)的[分组](https://baike.baidu.com/item/%E5%88%86%E7%BB%84/7360586)进行[加密](https://baike.baidu.com/item/%E5%8A%A0%E5%AF%86/752748)和[认证](https://baike.baidu.com/item/%E8%AE%A4%E8%AF%81/464259)来保护IP协议的[网络传输协议](https://baike.baidu.com/item/%E7%BD%91%E7%BB%9C%E4%BC%A0%E8%BE%93%E5%8D%8F%E8%AE%AE/332131)族（一些相互关联的协议的集合）。
IPsec主要由以下[协议](https://baike.baidu.com/item/%E5%8D%8F%E8%AE%AE)组成：
一、认证头（AH），为[IP数据报](https://baike.baidu.com/item/IP%E6%95%B0%E6%8D%AE%E6%8A%A5/1581132)提供无连接[数据完整性](https://baike.baidu.com/item/%E6%95%B0%E6%8D%AE%E5%AE%8C%E6%95%B4%E6%80%A7)、[消息认证](https://baike.baidu.com/item/%E6%B6%88%E6%81%AF%E8%AE%A4%E8%AF%81)以及防[重放攻击](https://baike.baidu.com/item/%E9%87%8D%E6%94%BE%E6%94%BB%E5%87%BB)保护；
二、封装安全载荷（ESP），提供机密性、数据源认证、无连接完整性、防重放和有限的传输流（traffic-flow）机密性；
三、安全关联（SA），提供算法和数据包，提供AH、ESP操作所需的参数。
四、密钥协议（[[IKE|IKE]]），提供对称密码的钥匙的生存和交换。

### AH
**认证头**（Authentication Header，**AH**）被用来保证被传输分组的完整性和可靠性。此外，它还保护不受[重放攻击](https://baike.baidu.com/item/%E9%87%8D%E6%94%BE%E6%94%BB%E5%87%BB)。认证头试图保护[IP数据报](https://baike.baidu.com/item/IP%E6%95%B0%E6%8D%AE%E6%8A%A5/1581132)的**所有字段**，那些在传输IP分组的过程中要发生变化的字段就只能被排除在外。当认证头使用非对称[数字签名算法](https://baike.baidu.com/item/%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D%E7%AE%97%E6%B3%95/12724298)（如RSA）时，可以提供不可否认性（RFC 1826）。
**它用来向 IP通信提供[数据完整性](https://baike.baidu.com/item/%E6%95%B0%E6%8D%AE%E5%AE%8C%E6%95%B4%E6%80%A7/110071)和身份验证,同时可以提供抗重播服务。**
不使用数字签名技术，使用安全哈希算法
HMAC-MD5和HMAC-SHA1

### ESP
**封装安全载荷**（Encapsulating Security Payload，**ESP**）协议对分组提供了源可靠性、完整性和保密性的支持。与AH头不同的是，**IP分组头部不被包括在内**。

