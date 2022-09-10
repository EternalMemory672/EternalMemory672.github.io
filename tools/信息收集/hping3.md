## hping3
#信息收集  #c段扫描
kali
```
hping3 host [options]

  -h  --help        	显示帮助
  -v  --version     	显示版本
  -c  --count       	发送数据包的数目
  -i  --interval    	发送数据包间隔的时间 (uX即X微秒, 例如： -i u1000)
      --fast        	等同 -i u10000 (每秒10个包)
      --faster      	等同 -i u1000 (每秒100个包)
      --flood       	尽最快发送数据包，不显示回复
  -n  --numeric     	数字化输出，象征性输出主机地址
  -q  --quiet       	安静模式
  -I  --interface   	网卡接口 (默认路由接口)
  -V  --verbose     	详细模式
  -D  --debug       	调试信息
  -z  --bind        	绑定 ctrl+z 到 ttl (默认为目的端口)
  -Z  --unbind      	取消绑定 ctrl+z 键
      --beep        	对于接收到的每个匹配数据包蜂鸣声提示
  
模式选择  
  default mode      	默认模式是TCP
  -0  --rawip       	RAW IP模式，原始IP模式。在此模式下Hping3会发送带数据的IP头。即裸IP方式。使用RAWSOCKET方式
  -1  --icmp        	ICMP模式，此模式下Hping3会发送IGMP应答报，你可以用 --icmptype,--icmpcode 选项发送其他类型/模式的ICMP报文
  -2  --udp         	UDP模式，默认Hping3会发送UDP报文到主机的0端口，你可以用 --baseport,--destport,--keep 选项指定端口
  -8  --scan        	扫描模式，扫描指定的端口
                    	Example: hping3 --scan 1-30,70-90 -S www.target.host
  -9  --listen      	监听模式
    
IP 模式  
  -a  --spoof       	源地址欺骗。伪造自身IP，对目的进行攻击，防火墙就不会记录你的真实IP了，当然回应的包你也接收不到了
  	  --rand-dest   	随机目的地址模式，详细使用 man 命令
      --rand-source 	随机源地址模式，详细使用 man 命令
  -t  --ttl         	指定 ttl 值 (默认 64)
  -N  --id          	hping3 中的 ID 值，缺省为随机值
  -W  --winid       	使用 win* id 字节顺序，针对不同的操作系统。UNIX,WINDIWS的id回应不同，这选项可以让你的ID回应和WINDOWS一样
  -r  --rel         	相对id字段(用于评估主机流量)  //更改ID的，可以让ID曾递减输出，详见HPING-HOWTO
  -f  --frag        	将数据包拆分成更多的frag，可能通过弱访问控制列表（acl）	//分段，可以测试对方或者交换机碎片处理能力，缺省16字节
  -x  --morefrag    	设置更多的分段标志    //大量碎片，泪滴攻击
  -y  --dontfrag    	设置不分段标志    //发送不可恢复的IP碎片，这可以让你了解更多的MTU PATH DISCOVERY
  -g  --fragoff     	set the fragment offset    //设置断偏移
  -m  --mtu         	设置虚拟最大传输单元，当大于MTU时分段；如果数据包大于MTU，等同于使用 --frag 选项
  -o  --tos         	tos字段，服务类型，缺省值为0x00，通过 hping3 --tos help 命令查看详细
  -G  --rroute     		记录IP路由，并显示路由缓冲
      --lsrr        	松散源路由并记录路由 (loose source routing and record route)
      --ssrr        	严格源路由并记录路由 (strict source routing and record route)
  -H  --ipproto     	设置IP协议字段，仅在RAW IP模式下使用
  
ICMP 模式
  -C  --icmptype    	icmp类型，默认回显(echo)请求
  -K  --icmpcode    	icmp代号，默认0
      --force-icmp  	发送所有icmp类型(默认仅发送支持的类型)
      --icmp-gw     	设置ICMP重定向网关地址(默认0.0.0.0)
      --icmp-ts     	等同 --icmp --icmptype 13 (ICMP 时间戳)
      --icmp-addr   	等同 --icmp --icmptype 17 (ICMP 地址子网掩码)
      --icmp-help   	显示其他icmp选项帮助
  
UDP/TCP 模式
  -s  --baseport    	设置源端口，默认为随机源端口
  -p  --destport    	设置目的端口，默认端口为0
  -k  --keep        	保持源端口不变
  -w  --win         	win的滑动窗口。windows发送字节(默认64)
  -O  --tcpoff      	set fake tcp data offset(instead of tcphdrlen / 4)    //设置伪造tcp数据偏移量(取代tcp地址长度/4)
  -Q  --seqnum      	仅显示tcp序列号
  -b  --badcksum    	(尝试)发送具有错误IP校验和的数据包，所以你会得到错误UDP/TCP校验和。但是许多系统会修复发送数据包的IP校验和
  -M  --setseq      	设置TCP序列号
  -L  --setack      	set TCP ack，不是 TCP 的 ACK 标志位
  -F  --fin         	set FIN flag  
  -S  --syn         	set SYN flag  
  -R  --rst         	set RST flag  
  -P  --push        	set PUSH flag  
  -A  --ack         	set ACK flag，设置 TCP 的 ACK 标志位
  -U  --urg         	set URG flag      //一大堆IP报头的设置
  -X  --xmas        	set X unused flag (0x40)
  -Y  --ymas        	set Y unused flag (0x80)
      --tcpexitcode     使用last tcp->th_flags 作为退出码
      --tcp-mss         使用给定的值启用TCP MSS选项
      --tcp-timestamp   启用TCP时间戳选项来猜测HZ/uptime
  
通用设置  
  -d  --data        	发送数据包的大小，默认为0
  -E  --file        	发送指定文件内的数据
  -e  --sign        	添加“签名”
  -j  --dump        	转储为十六进制数据包
  -J  --print       	转储为可打印字符
  -B  --safe        	启用“安全”协议
  -u  --end         	告诉你什么时候--file达到EOF并防止倒回
  -T  --traceroute  	traceroute模式(等同使用 --bind 且 --ttl 1)
      --tr-stop     	在traceroute模式下，收到第一个非ICMP报文时退出
      --tr-keep-ttl 	保持源TTL固定，仅用于监视一跳
      --tr-no-rtt   	不要在traceroute模式下计算或显示RTT信息

ARS packet description (new, unstable)
      --apd-send    	发送用APD描述的数据包(参见docs/APD.txt)

```