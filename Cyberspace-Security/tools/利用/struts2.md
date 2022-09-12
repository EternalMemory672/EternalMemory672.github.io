## struts2
#漏洞利用 
```
Usage: Struts2Scan.py [OPTIONS]

  Struts2批量扫描利用工具

Options:
  -i, --info          漏洞信息介绍
  -v, --version       显示工具版本
  -u, --url TEXT      URL地址
  -n, --name TEXT     指定漏洞名称, 漏洞名称详见info
  -f, --file TEXT     批量扫描URL文件, 一行一个URL
  -d, --data TEXT     POST参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}
  -c, --encode TEXT   页面编码, 默认UTF-8编码
  -p, --proxy TEXT    HTTP代理. 格式为http://ip:port
  -t, --timeout TEXT  HTTP超时时间, 默认10s
  -w, --workers TEXT  批量扫描进程数, 默认为10个进程
  --header TEXT       HTTP请求头, 格式为: key1=value1&key2=value2
  -e, --exec          进入命令执行shell
  --webpath           获取WEB路径
  -r, --reverse TEXT  反弹shell地址, 格式为ip:port
  --upfile TEXT       需要上传的文件路径和名称
  --uppath TEXT       上传的目录和名称, 如: /usr/local/tomcat/webapps/ROOT/shell.jsp
  -q, --quiet         关闭打印不存在漏洞的输出，只保留存在漏洞的输出
  -h, --help          Show this message and exit.
```