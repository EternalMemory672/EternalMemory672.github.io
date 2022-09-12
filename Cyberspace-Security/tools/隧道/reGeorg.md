## reGeorg
#隧道转发 
```
reGeorgSocksProxy.py [-h] [-l] [-p] [-r] -u  [-v]

Socks server for reGeorg HTTP(s) tunneller

optional arguments:
  -h, --help           show this help message and exit
  -l , --listen-on     The default listening address
  -p , --listen-port   The default listening port
  -r , --read-buff     Local read buffer, max data to be sent per POST
  -u , --url           The url containing the tunnel script
  -v , --verbose       Verbose output[INFO|DEBUG]

python2 reGeorgSocksProxy.py -p 80 -u http://192.168.1.132/tunnel.nosocket.php
```
![[../../attaches/Pasted image 20220911195127.png]]