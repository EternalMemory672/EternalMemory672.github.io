## dismap
#信息收集 #指纹识别
```
  -f, --file string     从文件中解析目标进行批量识别
  -h, --help            查看帮助说明
  -i, --ip string       指定一个网段 [示例 -i 192.168.1.0/24 or -i 192.168.1.1-10]
  -j, --json string     扫描结果保存到 json 格式文件
  -l, --level int       指定日志等级 (0:Fatal 1:Error 2:Info 3:Warning 4:Debug 5:Verbose) (默认 3)
  -m, --mode string     指定要识别的协议 [e.g. -m mysql/-m http]
      --nc              不打印字符颜色
      --np              不使用 ICMP/PING 检测存活主机
  -o, --output string   将扫描结果保存到指定文件 (默认 "output.txt")
  -p, --port string     自定义要识别的端口 [示例 -p 80,443 or -p	 1-65535]
      --proxy string    使用代理进行扫描, 支持 http/socks5 协议代理 [示例 --proxy socks5://127.0.0.1:1080]
  -t, --thread int      并发线程数量 (默认 500)
      --timeout int     超时时间 (默认 5)
      --type string     指定扫描类型 [示例 --type tcp/--type udp]
  -u, --uri string      指定目标地址 [示例 -u https://example.com]



zhzyker@debian:~$ ./dismap -i 192.168.1.1/24
zhzyker@debian:~$ ./dismap -i 192.168.1.1/24 -o result.txt -j result.json
zhzyker@debian:~$ ./dismap -i 192.168.1.1/24 --np --timeout 10
zhzyker@debian:~$ ./dismap -i 192.168.1.1/24 -t 1000
zhzyker@debian:~$ ./dismap -u https://github.com/zhzyker/dismap
zhzyker@debian:~$ ./dismap -u mysql://192.168.1.1:3306
zhzyker@debian:~$ ./dismap -i 192.168.1.1/24 -p 1-65535
```