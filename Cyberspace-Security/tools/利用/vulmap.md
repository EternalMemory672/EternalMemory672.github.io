## vulmap
#漏洞利用 
```
可选参数:
  -h, --help            显示此帮助消息并退出
  -u URL, --url URL     目标 URL (e.g. -u "http://example.com")
  -f FILE, --file FILE  选择一个目标列表文件,每个url必须用行来区分 (e.g. -f "/home/user/list.txt")
  --fofa keyword        使用 fofa api 批量扫描 (e.g. --fofa "app=Apache-Shiro")
  --shodan keyword      使用 shodan api 批量扫描 (e.g. --shodan "Shiro")
  -m MODE, --mode MODE  模式支持"poc"和"exp",可以省略此选项,默认进入"poc"模式
  -a APP [APP ...]      指定 webapps（e.g. "weblogic"）不指定则自动指纹识别
  -c CMD, --cmd CMD     自定义远程命令执行执行的命令,默认是echo随机md5
  -v VULN, --vuln VULN  利用漏洞,需要指定漏洞编号 (e.g. -v "CVE-2019-2729")
  -t NUM, --thread NUM  扫描线程数量,默认10线程
  --dnslog server       dnslog 服务器 (hyuga,dnslog,ceye) 默认自动轮询
  --output-text file    扫描结果输出到 txt 文件 (e.g. "result.txt")
  --output-json file    扫描结果输出到 json 文件 (e.g. "result.json")
  --proxy-socks SOCKS   使用 socks 代理 (e.g. --proxy-socks 127.0.0.1:1080)
  --proxy-http HTTP     使用 http 代理 (e.g. --proxy-http 127.0.0.1:8080)
  --user-agent UA       允许自定义 User-Agent
  --fofa-size SIZE      fofa api 调用资产数量，默认100，可用(1-10000)
  --delay DELAY         延时时间,每隔多久发送一次,默认 0s
  --timeout TIMEOUT     超时时间,默认 5s
  --list                显示支持的漏洞列表
  --debug               exp 模式显示 request 和 responses, poc 模式显示扫描漏洞列表
  --check               目标存活检测 (on and off), 默认是 on
```
```
# 测试所有漏洞 poc 不指定 -a all 将默认开启指纹识别
python3 vulmap.py -u http://example.com

# 检查站点是否存在 struts2 漏洞
python3 vulmap.py -u http://example.com -a struts2

# 对 http://example.com:7001 进行 WebLogic 的 CVE-2019-2729 漏洞利用
python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729
python3 vulmap.py -u http://example.com:7001 -m exp -v CVE-2019-2729

# 批量扫描 list.txt 中的 url
python3 vulmap.py -f list.txt

# 扫描结果导出到 result.json
python3 vulmap.py -u http://example.com:7001 --output-json result.json

# 调用 fofa api 批量扫描
python3 vulmap.py --fofa app=Apache-Shiro
```