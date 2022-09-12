# vulnstack
## vulnstack1
### 官方介绍
[vulnstack1官方地址](http://vulnstack.qiyuanxuetang.net/vuln/detail/2/)
红队实战系列，主要以真实企业环境为实例搭建一系列靶场，通过练习、视频教程、博客三位一体学习。另外本次实战完全模拟ATT&CK攻击链路进行搭建，开成完整闭环。后续也会搭建真实APT实战环境，从实战中成长。关于环境可以模拟出各种各样实战路线，目前给出作者实战的一套攻击实战路线如下，虚拟机所有统一密码：hongrisec@2019：
一、环境搭建  
1.环境搭建测试  
2.信息收集
二、漏洞利用  
3.漏洞搜索与利用  
4.后台Getshell上传技巧  
5.系统信息收集  
6.主机密码收集
三、内网搜集  
7.内网--继续信息收集  
8.内网攻击姿势--信息泄露  
9.内网攻击姿势-MS08-067  
10.内网攻击姿势-SMB远程桌面口令猜测  
11.内网攻击姿势-Oracle数据库TNS服务漏洞  
12.内网攻击姿势-RPC DCOM服务漏洞
四、横向移动  
13.内网其它主机端口-文件读取  
14.内网其它主机端口-redis  
15.内网其它主机端口-redis Getshell  
16.内网其它主机端口-MySQL数据库  
17.内网其它主机端口-MySQL提权
五、构建通道  
18.内网其它主机端口-代理转发
六、持久控制  
19.域渗透-域成员信息收集  
20.域渗透-基础服务弱口令探测及深度利用之powershell  
21.域渗透-横向移动[wmi利用]  
22.域渗透-C2命令执行  
23.域渗透-利用DomainFronting实现对beacon的深度隐藏  
24.域渗透-域控实现与利用
七、痕迹清理  
25、日志清理
### 环境搭建
#### 网络配置
web服务器 win 7 桥接模式&仅主机模式（192.168.52.143 / 192.168.1.9），登录后进入`C:\phpStudy`启动小皮面板。
![](../attaches/Pasted%20image%2020220912140046.png)
![](../attaches/Pasted%20image%2020220912143035.png)
域控win sevrer 2008 仅主机模式（192.168.52.138）
![](../attaches/Pasted%20image%2020220912133423.png)
域成员 win server 2003 仅主机模式（192.168.52.141）
![](../attaches/Pasted%20image%2020220912134042.png)
攻击机 kali 桥接模式（192.168.1.131）
![](../attaches/Pasted%20image%2020220912134128.png)
#### 域配置
登录winserver2008配置ipv4属性如下，dns修改为192.168.52.138，此后`ping god.org`通则成功。
![](../attaches/Pasted%20image%2020220912140924.png)
### 信息收集
使用`netdiscover -i eth0 -r 192.168.1.0/24`（arp方式，目标开启防火墙时有奇效）或`nmap -sP -T4 192.168.1.0/24` 对当前C段主机进行存活扫描
netdiscover扫描结果如下
![](../attaches/Pasted%20image%2020220912154711.png)

192.168.1.1一般为网关地址，结合zte corporation判断其为中兴的网关系统。

192.168.1.2是物理机IP地址，予以排除。

192.168.1.5是TP-LINK的设备，应为路由器，予以排除。

192.168.1.8为鸿海精工代工的某设备，一般为电视或打印机等，予以排除。

192.168.1.9为VMware虚拟机，确定为目标机。

如下为nmap的扫描结果，与上相似。
![](../attaches/Pasted%20image%2020220912155934.png)

使用`sudo nmap -sC -sV -Pn -O -p- 192.168.1.9`扫描目标机的开放端口。
``` shell
sudo nmap -sC -sV -Pn -O -p- 192.168.1.9
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-12 03:59 EDT
Nmap scan report for bogon (192.168.1.9)
Host is up (0.00030s latency).
Not shown: 65523 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.4.45)
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45
|_http-title: phpStudy \xE6\x8E\xA2\xE9\x92\x88 2014 
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: GOD)
1025/tcp open  msrpc        Microsoft Windows RPC
1026/tcp open  msrpc        Microsoft Windows RPC
1027/tcp open  msrpc        Microsoft Windows RPC
1028/tcp open  msrpc        Microsoft Windows RPC
1029/tcp open  msrpc        Microsoft Windows RPC
1083/tcp open  msrpc        Microsoft Windows RPC
3306/tcp open  mysql        MySQL (unauthorized)
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
MAC Address: 00:0C:29:57:52:B5 (VMware)
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: STU1; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: stu1
|   NetBIOS computer name: STU1\x00
|   Domain name: god.org
|   Forest name: god.org
|   FQDN: stu1.god.org
|_  System time: 2022-09-12T16:01:22+08:00
|_clock-skew: mean: -2h40m00s, deviation: 4h37m07s, median: -1s
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: STU1, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:57:52:b5 (VMware)
| smb2-time: 
|   date: 2022-09-12T08:01:22
|_  start_date: 2022-09-12T05:54:10
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.99 seconds
```
## vulnstack2
### 官方介绍
红队实战系列，主要以真实企业环境为实例搭建一系列靶场，通过练习、视频教程、博客三位一体学习。本次红队环境主要Access Token利用、WMI利用、域漏洞利用SMB relay，EWS relay，PTT(PTC)，MS14-068，GPP，SPN利用、黄金票据/白银票据/Sid History/MOF等攻防技术。关于靶场统一登录密码：1qaz@WSX
1.  Bypass UAC
2.  Windows系统NTLM获取（理论知识：Windows认证）
3.  Access Token利用（MSSQL利用）
4.  WMI利用
5.  网页代理，二层代理，特殊协议代理（DNS，ICMP）
6.  域内信息收集
7.  域漏洞利用：SMB relay，EWS relay，PTT(PTC)，MS14-068，GPP，SPN利用
8.  域凭证收集
9.  后门技术（黄金票据/白银票据/Sid History/MOF）
#### 环境说明
内网网段：10.10.10.1/24
DMZ网段：192.168.111.1/24
测试机地址：192.168.111.1（Windows），192.168.111.11（Linux）
防火墙策略（策略设置过后，测试机只能访问192段地址，模拟公网访问）：
deny all tcp ports：10.10.10.1
allow all tcp ports：10.10.10.0/24
#### 配置信息
**DC**
IP：10.10.10.10OS：Windows 2012(64)
应用：AD域
**WEB**
IP1：10.10.10.80IP2：192.168.111.80OS：Windows 2008(64)
应用：Weblogic 10.3.6MSSQL 2008
**PC**
IP1：10.10.10.201IP2：192.168.111.201OS：Windows 7(32)
应用：
**攻击机**
IP：192.168.111.1OS：Windows 10(64)
IP：192.168.111.11OS：Parrot(64)
## vulnstack3
### 官方介绍
基本信息
**作者：**licong
环境配置
**打开虚拟机镜像为挂起状态，第一时间进行快照，部分服务未做自启，重启后无法自动运行。**
**挂起状态，账号已默认登陆，centos为出网机，第一次运行，需重新获取桥接模式网卡ip。**
**除重新获取ip，不建议进行任何虚拟机操作。**
参考虚拟机网络配置，添加新的网络，该网络作为内部网络。
**注：名称及网段必须符合上述图片，进行了固定ip配置。**
描述
**目标：域控中存在一份重要文件。**
本次环境为黑盒测试，不提供虚拟机账号密码。
## vulnstack4
### 官方介绍
大家好红日安全红队靶场（四）已经出来，本次靶场渗透**反序列化漏洞、命令执行漏洞、Tomcat漏洞、MS系列漏洞、端口转发漏洞、以及域渗透**等多种组合漏洞，希望大家多多利用。
#### 红队评估四靶场描述
**第一次搭建靶机，如有啥不足或问题，欢迎各位师傅在vlunstack微信群里提出，向师傅们学习**
其它靶场下载地址
-   红队评估一：[http://vulnstack.qiyuanxuetang.net/vuln/detail/2/](http://vulnstack.qiyuanxuetang.net/vuln/detail/2/)
-   红队评估二：[http://vulnstack.qiyuanxuetang.net/vuln/detail/3/](http://vulnstack.qiyuanxuetang.net/vuln/detail/3/)
-   红队评估三：[http://vulnstack.qiyuanxuetang.net/vuln/detail/5/](http://vulnstack.qiyuanxuetang.net/vuln/detail/5/)
-   Web安全靶场下载：[http://vulnstack.qiyuanxuetang.net/vuln/detail/4/](http://vulnstack.qiyuanxuetang.net/vuln/detail/4/)
#### 靶场学习路径，可参考
-   st漏洞利用
-   phpmyadmin getshell
-   tomcat 漏洞利用
-   docker逃逸
-   ms14-068
-   ssh密钥利用
-   流量转发
-   历史命令信息泄露
-   域渗透
#### 环境说明
**机器密码**
-   ubuntu:ubuntu**域成员机器**
-   douser:Dotest123**DC:**
-   administrator:Test2008
## vulnstack5
### 官方介绍
大家好，ATT&CK第五个攻防靶场已经出来了，此次靶场虚拟机共用两个，一个外网一个内网，用来练习红队相关内容和方向，主要包括常规信息收集、Web攻防、代码审计、漏洞利用、内网渗透以及域渗透等相关内容学习，此靶场主要用来学习，请大家遵守网络网络安全法。
#### 描述
##### 虚拟机密码
**win7**
`sun\heart 123.com`
`sun\Administrator dc123.com`
**2008**
`sun\admin 2020.com`
Win7双网卡模拟内外网
#### 红队思路
**一、环境搭建**
-   1.环境搭建测试
-   2.信息收集
**二、漏洞利用**
-   3.漏洞搜索与利用
-   4.漏洞利用Getshell
-   5.系统信息收集
-   6.主机密码收集
**三、内网搜集**
-   7.内网--继续信息收集
-   8.内网攻击姿势--MS14-058
-   9.内网攻击姿势--MS17-010
**四、横向移动**
-   10.psexec远控
-   11.内网其它主机端口
-   12.netsh增删防火墙规则
**五、构建通道**
-   13.内网其它主机端口-代理转发
**六、持久控制**
-   14.域渗透-域成员信息收集
-   15.域渗透-基础服务弱口令探测及深度利用之powershell
-   16.域渗透-横向移动[wmi利用]
-   17.域渗透-域控实现与利用
**七、痕迹清理**
-   18、日志清理
## vulnstack6
### 官方介绍
大家好，ATT&CK第六个攻防靶场，当前第六、七靶场为蓝队职业体系课程，vulnstack也开源分享出来，目前此套靶场已经录制视频教程，因蓝队体系是收费课程，所以大家根据自己需求选择。本次主要考核内容为从某CMS漏洞然后打入内网然后到域控，主要包括常规信息收集、Web攻防、代码审计、漏洞利用、内网渗透以及域渗透等相关内容学习，此靶场主要用来学习，请大家遵守网络网络安全法。
此次红队评估两个靶场结合蓝队的环境，一共会搭建两个，如下
-   **实验思路**
    -   某CMS漏洞渗透某内网域控
    -   代码审计渗透到内网域控
#### 拓扑图
#### 环境
WEB IP:192.168.111.80
DC IP:10.10.10.10
本机 VMnet1
IP:10.10.10.1;
本机 VMnet8
IP:192.168.111.1
恢复快照 3.1，本机配置好 IP，可 ping 通 10.10.10.10，可远程桌面 192.168.111.80 即可，模拟环境，本机使用 192 地址操作。
#### 实验目的
获取 DC 服务器权限
#### 视频课程
[http://qiyuanxuetang.net/courses/detail/30/](http://vulnstack.qiyuanxuetang.net/vuln/detail/8/)
## vulnstack7
### 官方介绍
大家好，第七个ATT&CK综合性靶场和大家见面了，第七个靶场为投稿靶场，也希望大家踊跃投稿。主要包括常规信息收集、Web攻防、代码审计、漏洞利用、内网渗透以及域渗透等相关内容学习，此靶场主要用来学习，请大家遵守网络网络安全法。
#### **ATT&CK模拟攻击路径**
ATT&CK模拟攻击路径,2021年红日重新打造ATT&CK靶场，结合ATT&CK最新攻击实战TTP，然后把相关路径结合到靶场当中，当练习者可以从攻击过程中学习到这个框架带来的好处，由于攻击方法太多，所以会选取一些具备代表性内容，可能也会选取一些APT案例。
-   Active Scanning-T1595
-   Exploit Public-facing Application-T1190
-   Command and Interpreter-T1059
-   Scheduled Task/Job-T1053
-   Boot or Logon Autostart Execution-T1547
-   Brute-Force-T1110
-   Input Capture-T1056
-   OS Credential Dumping-T1003
-   Remote Service-T1021
-   Application Layer Protocal-T1071
#### **环境说明**
DMZ区IP段为192.168.1.1/24
-   第二层网络环境IP段为192.168.52.1/24
-   第三层网络环境IP段为192.168.93.1/24
#### **环境配置**
在Vmware中新增两个虚拟网卡VMnet8、VMnet14。VMnet8设为默认的NAT模式，IP段设为192.168.52.0/24；VMnet14设为仅主机模式，IP段设为192.168.93.0/24：
将VMnet8作为第二层网络的网卡，VMnet14作为第三层网络的网卡。这样，第二层网络中的所有主机皆可以上网，但是位于第三层网络中的所有主机都不与外网相连通，不能上网。
**DMZ区域：**
-   给Ubuntu (Web 1) 配置了两个网卡，一个桥接可以对外提供服务；一个连接在VMnet8上连通第二层网络。
**第二层网络区域：**
-   给Ubuntu (Web 2) 和Windows 7 (PC 1)都配置了两个网卡，一个连接在VMnet8上连通第二层网络，一个连接在VMnet14上连通第三层网络。
**第三次网络区域：**
-   给Windows Server 2012和Windows 7 (PC 2)都只配置了一个网卡，一个连接在VMnet14上连通第三层网络。
#### **服务配置**
靶场中各个主机都运行着相应的服务并且没有自启功能，如果你关闭了靶机，再次启动时还需要在相应的主机上启动靶机服务：
**DMZ区的 Ubuntu 需要启动redis和nginx服务：**
-   redis-server /etc/redis.conf
-   /usr/sbin/nginx -c /etc/nginx/nginx.conf
-   iptables -F
**第二层网络的 Ubuntu需要启动docker容器：**
-   sudo service docker start
-   sudo docker start 8e172820ac78
**第三层网络的 Windows 7 （PC 1）需要启动通达OA：**
-   `C:\MYOA\bin\AutoConfig.exe`
#### **域用户信息**
域用户账户和密码如下：
-   Administrator：Whoami2021
-   whoami：Whoami2021
-   bunny：Bunny2021
-   moretz：Moretz2021
Ubuntu 1：
-   web：web2021
Ubuntu 2：
-   ubuntu：ubuntu
通达OA账户：
-   admin：admin657260
#### **靶场涉及知识点**
**信息收集：**
-   端口扫描
-   端口服务识别
**漏洞利用：**
-   漏洞搜索与利用
-   Laravel Debug mode RCE（CVE-2021-3129）漏洞利用
-   Docker逃逸
-   通达OA v11.3 漏洞利用
-   Linux环境变量提权
-   Redis 未授权访问漏洞
-   Linux sudo权限提升（CVE-2021-3156）漏洞利用
-   SSH密钥利用
-   Windows NetLogon 域内权限提升（CVE-2020-1472）漏洞利用
-   MS14-068漏洞利用
**构建隧道：**
-   路由转发与代理
    -   二层网络代理
    -   三层网络代理
**横向移动：**
-   内网（域内）信息收集
-   MS17-010
-   Windows系统NTLM与用户凭据获取
-   SMB Relay攻击
-   Psexec远控利用
-   哈希传递攻击（PTH）
-   WMI利用
-   DCOM利用
**权限维持：**
-   黄金票据
-   白银票据
-   Sid History
#### **靶场WriteUp**
[https://www.freebuf.com/articles/network/264560.html](https://www.freebuf.com/articles/network/264560.html)