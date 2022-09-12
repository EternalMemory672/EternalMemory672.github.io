## oneforall
#信息收集 #子域名爆破
win/kali
```
INFO: Showing help with the command 'oneforall.py -- --help'.

NAME
    oneforall.py - OneForAll help summary page

SYNOPSIS
    oneforall.py COMMAND | <flags>

DESCRIPTION
    OneForAll is a powerful subdomain integration tool

    Example:
        python3 oneforall.py version
        python3 oneforall.py check
        python3 oneforall.py --target example.com run
        python3 oneforall.py --targets ./domains.txt run
        python3 oneforall.py --target example.com --alive False run
        python3 oneforall.py --target example.com --brute False run
        python3 oneforall.py --target example.com --port medium run
        python3 oneforall.py --target example.com --fmt csv run
        python3 oneforall.py --target example.com --dns False run
        python3 oneforall.py --target example.com --req False run
        python3 oneforall.py --target example.com --takeover False run
        python3 oneforall.py --target example.com --show True run

    Note:
        --port   small/medium/large  See details in ./config/setting.py(default small)
        --fmt csv/json (result format)
        --path   Result path (default None, automatically generated)

FLAGS
    --target=TARGET
        Type: Optional[]
        Default: None
        One domain (target or targets must be provided)
    --targets=TARGETS
        Type: Optional[]
        Default: None
        File path of one domain per line
    --brute=BRUTE
        Type: Optional[]
        Default: None
        Use brute module (default True)
    --dns=DNS
        Type: Optional[]
        Default: None
        Use DNS resolution (default True)
    --req=REQ
        Type: Optional[]
        Default: None
        HTTP request subdomains (default True)
    --port=PORT
        Type: Optional[]
        Default: None
        The port range to request (default small port is 80,443)
    --alive=ALIVE
        Type: Optional[]
        Default: None
        Only export alive subdomains (default False)
    --fmt=FMT
        Type: Optional[]
        Default: None
        Result format (default csv)
    --path=PATH
        Type: Optional[]
        Default: None
        Result path (default None, automatically generated)
    --takeover=TAKEOVER
        Type: Optional[]
        Default: None
        Scan subdomain takeover (default False)

COMMANDS
    COMMAND is one of the following:

     check
       Check if there is a new version and exit

     version
       Print version information and exit
```